#if defined(__APPLE__)

#include "kqueue_connection.hpp"

#include "http/common/http_error_msgs.hpp"
#include "http/common/http_global_state.hpp"
#include "http/ssl/http_ssl_factory.hpp"

#include <sys/socket.h>
#include <sys/event.h>   // kqueue, kevent, EV_SET

#include <fcntl.h>
#include <unistd.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <errno.h>

namespace WFX::OSSpecific {

// =============================================================================
// NOTE ON macOS sendfile vs Linux sendfile
//
//  Linux:  ssize_t sendfile(int out_fd, int in_fd, off_t* offset, size_t count)
//              returns bytes sent, or -1
//
//  macOS:  int     sendfile(int fd, int s, off_t offset, off_t* len,
//                           struct sf_hdtr* hdtr, int flags)
//              *len is IN/OUT: pass bytes-to-send, get bytes-actually-sent
//              returns 0 on success/partial, -1 on error
//              EAGAIN means partial send (check *len for progress)
//
// WrapFile() below handles this difference so the rest of the class
// can stay identical to the epoll implementation.
// =============================================================================


// =============================================================================
// Constructor & Destructor
// =============================================================================

KqueueConnectionHandler::KqueueConnectionHandler(bool useHttps)
    : useHttps_(useHttps)
{
    if(useHttps)
        sslHandler_ = CreateSSLHandler();
}

KqueueConnectionHandler::~KqueueConnectionHandler()
{
    if(listenFd_ > 0) { close(listenFd_); listenFd_ = -1; }
    if(kqFd_     > 0) { close(kqFd_);     kqFd_     = -1; }

    logger_.Info("[Kqueue]: Cleaned up resources successfully");
}


// =============================================================================
// Initializing
// =============================================================================

void KqueueConnectionHandler::Initialize(const std::string& host, int port)
{
    auto& osConfig      = config_.osSpecificConfig;
    auto& networkConfig = config_.networkConfig;

    // ---- Connection pool setup (identical to epoll) ----
    constexpr std::uint32_t MAX_64_ALIGNED = 0xFFFF'FFC0u;

    std::uint64_t rounded = std::uint64_t(networkConfig.maxConnections) + 63;
    rounded &= ~std::uint64_t(63);
    if(rounded > MAX_64_ALIGNED)
        rounded = MAX_64_ALIGNED;

    connSlots_ = std::uint32_t(rounded);
    connWords_ = connSlots_ >> 6;

    connections_ = std::make_unique<ConnectionContext[]>(connSlots_);
    connBitmap_  = std::make_unique<std::uint64_t[]>(connWords_);
    events_      = std::make_unique<struct kevent[]>(maxEvents_);

    std::fill_n(connBitmap_.get(), connWords_, 0);

    // ---- Create listening socket ----
    listenFd_ = socket(AF_INET, SOCK_STREAM, 0);
    if(listenFd_ < 0)
        logger_.Fatal("[Kqueue]: Failed to create listening socket: ", strerror(errno));

    int opt = 1;
    if(setsockopt(listenFd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
        logger_.Fatal("[Kqueue]: Failed to set SO_REUSEADDR: ", strerror(errno));

    // NOTE: SO_REUSEPORT exists on macOS too, keep it.
    if(setsockopt(listenFd_, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0)
        logger_.Fatal("[Kqueue]: Failed to set SO_REUSEPORT: ", strerror(errno));

    if(!SetNonBlocking(listenFd_))
        logger_.Fatal("[Kqueue]: Failed to make listening socket non-blocking: ", strerror(errno));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    if(!ResolveHostToIpv4(host.c_str(), &addr.sin_addr))
        logger_.Fatal("[Kqueue]: Failed to resolve host '", host, '\'');

    if(bind(listenFd_, (sockaddr*)&addr, sizeof(addr)) < 0)
        logger_.Fatal("[Kqueue]: Failed to bind socket: ", strerror(errno));

    if(listen(listenFd_, osConfig.backlog) < 0)
        logger_.Fatal("[Kqueue]: Failed to listen: ", strerror(errno));

    // ---- Create kqueue ----
    kqFd_ = kqueue();
    if(kqFd_ < 0)
        logger_.Fatal("[Kqueue]: Failed to create kqueue: ", strerror(errno));

    // Watch listen socket for incoming connections (EVFILT_READ)
    KqAdd(listenFd_, EVFILT_READ, nullptr); // nullptr udata = special fd, not a connection

    // ---- Timeout timer (drives TimerWheel, fires every INVOKE_TIMEOUT_COOLDOWN seconds) ----
    timerWheel_.Init(
        connSlots_,
        1024, 1, TimeUnit::SECONDS,
        [this](std::uint32_t connId) {
            ConnectionContext* ctx = &connections_[connId];
            if(
                ctx->GetConnectionState() != ConnectionState::CONNECTION_CLOSE
                || ctx->IsAsyncOperation()
            )
                Close(ctx, true);
        }
    );

    // EVFILT_TIMER: ident=TIMEOUT_TIMER_ID, period in milliseconds
    // This fires every INVOKE_TIMEOUT_COOLDOWN * 1000 ms and is NOT one-shot.
    KqSetTimer(TIMEOUT_TIMER_ID, INVOKE_TIMEOUT_DELAY * 1000, false);

    // ---- Async timer placeholder ----
    // The async timer is one-shot and gets rescheduled by UpdateAsyncTimer().
    // We don't arm it here; UpdateAsyncTimer() will arm it when needed.
}

void KqueueConnectionHandler::SetEngineCallbacks(ReceiveCallback onData, CompletionCallback onComplete)
{
    onReceive_         = std::move(onData);
    onAsyncCompletion_ = std::move(onComplete);
}


// =============================================================================
// I/O Operations  (logic identical to epoll; only the "re-arm" calls differ)
// =============================================================================

void KqueueConnectionHandler::ResumeReceive(ConnectionContext* ctx)
{
    if(!EnsureReadReady(ctx))
        return;
    ctx->eventType = EventType::EVENT_RECV;
}

void KqueueConnectionHandler::Write(ConnectionContext* ctx, std::string_view msg)
{
    // Case 1: fire-and-forget direct send (error codes, 100-Continue, etc.)
    if(!msg.empty()) {
        (void)WrapWrite(ctx, msg.data(), msg.size());
        goto __CleanupOrRearm;
    }

    // Case 2: send from buffer
    else {
        auto* writeMeta = ctx->rwBuffer.GetWriteMeta();
        if(!writeMeta || writeMeta->writtenLength >= writeMeta->dataLength)
            goto __CleanupOrRearm;

        while(writeMeta->writtenLength < writeMeta->dataLength) {
            const char* buf       = ctx->rwBuffer.GetWriteData() + writeMeta->writtenLength;
            std::size_t remaining = writeMeta->dataLength - writeMeta->writtenLength;

            ssize_t n = WrapWrite(ctx, buf, remaining);

            if(n > 0)
                writeMeta->writtenLength += n;

            else if(n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                // Socket not ready — arm EVFILT_WRITE and wait
                ctx->eventType = EventType::EVENT_SEND;
                return;
            }

            else {
                Close(ctx);
                return;
            }
        }
    }

__CleanupOrRearm:
    if(ctx->streamGenerator) { ResumeStream(ctx); return; }
    if(ctx->isFileOperation)  { SendFile(ctx);     return; }

    if(ctx->GetConnectionState() == ConnectionState::CONNECTION_CLOSE)
        Close(ctx);
    else {
        ctx->ClearContext();
        ResumeReceive(ctx);
    }
}

void KqueueConnectionHandler::WriteFile(ConnectionContext* ctx, std::string path)
{
    if(!EnsureFileReady(ctx, std::move(path))) {
        ctx->SetConnectionState(ConnectionState::CONNECTION_CLOSE);
        Write(ctx, HttpError::internalError);
        return;
    }
    ctx->isFileOperation = 1;
    Write(ctx, {});
}

void KqueueConnectionHandler::Stream(ConnectionContext* ctx, StreamGenerator generator, bool streamChunked)
{
    if(!generator) {
        logger_.Error("[Kqueue]: Stream() called with null generator");
        Close(ctx);
        return;
    }
    ctx->streamGenerator   = std::move(generator);
    ctx->isStreamOperation = 1;
    ctx->streamChunked     = streamChunked;
    Write(ctx, {});
}

void KqueueConnectionHandler::Close(ConnectionContext* ctx, bool forceClose)
{
    if(!ctx) return;
    if(!forceClose && ctx->isShuttingDown) return;

    ctx->isShuttingDown = 1;

    if(ctx->sslConn) {
        if(forceClose) {
            sslHandler_->ForceShutdown(ctx->sslConn);
            ctx->sslConn = nullptr;
        }
        else {
            auto res = sslHandler_->Shutdown(ctx->sslConn);
            if(res == SSLReturn::SUCCESS || res == SSLReturn::FATAL)
                ctx->sslConn = nullptr;
            else {
                ctx->eventType = EventType::EVENT_SHUTDOWN;
                return;
            }
        }
    }

    // Remove from kqueue before closing the fd
    // (deleting a non-existent filter is harmless — kqueue ignores it)
    KqDel(ctx->socket, EVFILT_READ);
    KqDel(ctx->socket, EVFILT_WRITE);
    ReleaseConnection(ctx);
}


// =============================================================================
// Main Event Loop
// =============================================================================

void KqueueConnectionHandler::Run()
{
    if(!onReceive_ || !onAsyncCompletion_)
        logger_.Fatal(
            "[Kqueue]: 'onReceive_' or 'onAsyncCompletion_' not initialised."
            " Call SetEngineCallbacks before Run."
        );

    while(running_) {
        // kevent() with no changelist and a NULL timeout = block indefinitely.
        int nfds = kevent(kqFd_, nullptr, 0, events_.get(), maxEvents_, nullptr);

        if(nfds < 0) {
            if(errno == EINTR) continue;
            break;
        }

        for(int i = 0; i < nfds; i++) {
            struct kevent& ev = events_[i];

            // ----------------------------------------------------------------
            // EVFILT_TIMER events — identified by their ident constant
            // ----------------------------------------------------------------
            if(ev.filter == EVFILT_TIMER) {

                if(ev.ident == TIMEOUT_TIMER_ID) {
                    std::uint64_t nowSec = NowMs() / 1000;
                    timerWheel_.Tick(nowSec);
                    logger_.Info("<TimeoutTimer>: ", numConnectionsAlive_, ' ', nowSec);
                    continue;
                }

                if(ev.ident == ASYNC_TIMER_ID) {
                    std::uint64_t newTick = NowMs();
                    std::uint64_t connId  = 0;

                    while(timerHeap_.PopExpired(newTick, connId)) {
                        ConnectionContext* ctx = &connections_[connId];
                        ctx->isAsyncTimerOperation = 0;

                        switch(ctx->TryFinishCoroutines()) {
                            case Async::Status::COMPLETED:
                                onAsyncCompletion_(ctx);
                                break;

                            case Async::Status::TIMER_FAILURE:
                            case Async::Status::IO_FAILURE:
                            case Async::Status::INTERNAL_FAILURE:
                                ctx->SetConnectionState(ConnectionState::CONNECTION_CLOSE);
                                Write(ctx, HttpError::internalError);
                                break;
                        }
                    }

                    // Async timer is one-shot; rearm for the next pending entry
                    UpdateAsyncTimer();
                    logger_.Info("<AsyncTimer>: ", numConnectionsAlive_, ' ', newTick);
                    continue;
                }

                continue; // Unknown timer id — ignore
            }

            // ----------------------------------------------------------------
            // Listen socket — accept new connections
            // ----------------------------------------------------------------
            if((int)ev.ident == listenFd_) {
                while(true) {
                    sockaddr_in clientAddr{};
                    socklen_t   addrLen = sizeof(clientAddr);

                    // macOS does not have accept4(); use accept() + fcntl()
                    int clientFd = accept(listenFd_, (sockaddr*)&clientAddr, &addrLen);
                    if(clientFd < 0) {
                        if(errno == EAGAIN || errno == EWOULDBLOCK) break;
                        else continue;
                    }

                    if(!SetNonBlocking(clientFd)) {
                        close(clientFd);
                        continue;
                    }

                    // Extract IP
                    WFXIpAddress tmpIp;
                    sockaddr* sa = reinterpret_cast<sockaddr*>(&clientAddr);
                    if(sa->sa_family == AF_INET) {
                        tmpIp.ip.v4  = reinterpret_cast<sockaddr_in*>(sa)->sin_addr;
                        tmpIp.ipType = AF_INET;
                    }
                    else if(sa->sa_family == AF_INET6) {
                        tmpIp.ip.v6  = reinterpret_cast<sockaddr_in6*>(sa)->sin6_addr;
                        tmpIp.ipType = AF_INET6;
                    }
                    else {
                        close(clientFd);
                        continue;
                    }

                    ConnectionContext* ctx = nullptr;
                    if(!ipLimiter_.AllowConnection(tmpIp) || !(ctx = GetConnection())) {
                        close(clientFd);
                        continue;
                    }

                    ctx->socket   = clientFd;
                    ctx->connInfo = tmpIp;

                    numConnectionsAlive_++;
                    WrapAccept(ctx);
                }
                continue;
            }

            // ----------------------------------------------------------------
            // Existing connection event
            // ----------------------------------------------------------------

            // We stored (generationId << 32 | slotIndex) in udata when we called KqAdd.
            std::uint64_t meta = reinterpret_cast<std::uint64_t>(ev.udata);
            std::uint32_t gen  = static_cast<std::uint32_t>(meta >> 32);
            std::uint32_t idx  = static_cast<std::uint32_t>(meta & 0xFFFFFFFF);

            // Stale event (connection was already recycled)
            if(idx >= connSlots_) continue;
            ConnectionContext* ctx = &connections_[idx];
            if(ctx->generationId != gen) continue;

            // kqueue reports errors via EV_EOF or EV_ERROR flags
            if(ev.flags & EV_ERROR) {
                Close(ctx);
                continue;
            }

            // SSL handshake in progress
            if(ctx->eventType == EventType::EVENT_HANDSHAKE) {
                SSLReturn hsResult = sslHandler_->Handshake(ctx->sslConn);
                switch(hsResult) {
                    case SSLReturn::SUCCESS:
                        ctx->eventType = EventType::EVENT_RECV;
                        if(ev.filter == EVFILT_READ)
                            Receive(ctx);
                        break;
                    case SSLReturn::WANT_READ:
                    case SSLReturn::WANT_WRITE:
                        break;
                    default:
                        Close(ctx);
                        break;
                }
                continue;
            }

            // SSL shutdown in progress
            if(ctx->eventType == EventType::EVENT_SHUTDOWN) {
                auto res = sslHandler_->Shutdown(ctx->sslConn);
                switch(res) {
                    case SSLReturn::WANT_READ:
                    case SSLReturn::WANT_WRITE:
                        break;
                    default:
                        ctx->sslConn = nullptr;
                        KqDel(ctx->socket, EVFILT_READ);
                        KqDel(ctx->socket, EVFILT_WRITE);
                        ReleaseConnection(ctx);
                        break;
                }
                continue;
            }

            // EV_EOF: peer closed the connection
            if(ev.flags & EV_EOF) {
                Close(ctx);
                continue;
            }

            // ---- Readable (EVFILT_READ) ----
            if(ev.filter == EVFILT_READ && ctx->eventType == EventType::EVENT_RECV) {
                if(!ipLimiter_.AllowRequest(ctx->connInfo)) {
                    ctx->SetConnectionState(ConnectionState::CONNECTION_CLOSE);
                    Write(ctx, HttpError::tooManyRequests);
                    continue;
                }
                Receive(ctx);
            }

            // ---- Writable (EVFILT_WRITE) ----
            if(ev.filter == EVFILT_WRITE) {
                if(ctx->eventType == EventType::EVENT_SEND_FILE)
                    SendFile(ctx);
                else if(ctx->eventType == EventType::EVENT_SEND)
                    Write(ctx, {});
            }
        }
    }
}

void KqueueConnectionHandler::RefreshExpiry(ConnectionContext* ctx, std::uint16_t timeoutSeconds)
{
    std::uint32_t idx = ctx - &connections_[0];
    timerWheel_.Schedule(idx, timeoutSeconds);
}

bool KqueueConnectionHandler::RefreshAsyncTimer(ConnectionContext* ctx, std::uint32_t delayMilliseconds)
{
    std::uint32_t idx    = ctx - &connections_[0];
    std::uint64_t expire = NowMs() + delayMilliseconds;

    if(!timerHeap_.Insert(idx, expire, 10)) {
        logger_.Warn("[Kqueue]: Failed to refresh async timer");
        return false;
    }

    ctx->isAsyncTimerOperation = 1;
    UpdateAsyncTimer();
    return true;
}

void KqueueConnectionHandler::Stop()
{
    running_ = false;
}


// =============================================================================
// Helper Functions — Connection Pool  (identical to epoll)
// =============================================================================

std::int64_t KqueueConnectionHandler::AllocSlot(std::uint64_t* bitmap, std::uint32_t numWords)
{
    std::uint32_t w = connLastIndex_;

    for(; w < numWords; ++w) {
        std::uint64_t inv = ~bitmap[w];
        if(inv) {
            int bit = __builtin_ctzll(inv);
            bitmap[w] |= 1ULL << bit;
            connLastIndex_ = w;
            return (std::int64_t(w) << 6) + bit;
        }
    }

    w = 0;
    for(; w < connLastIndex_; ++w) {
        std::uint64_t inv = ~bitmap[w];
        if(inv) {
            int bit = __builtin_ctzll(inv);
            bitmap[w] |= 1ULL << bit;
            connLastIndex_ = w;
            return (std::int64_t(w) << 6) + bit;
        }
    }

    return -1;
}

void KqueueConnectionHandler::FreeSlot(std::uint64_t* bitmap, std::uint32_t idx)
{
    std::uint32_t w   = idx >> 6;
    std::uint32_t bit = idx & 63;
    bitmap[w] &= ~(1ULL << bit);
}

ConnectionContext* KqueueConnectionHandler::GetConnection()
{
    std::int64_t idx = AllocSlot(connBitmap_.get(), connWords_);
    if(idx < 0) return nullptr;

    auto* ctx = &connections_[idx];
    ctx->generationId++;
    if(ctx->generationId == 0)
        ctx->generationId = 1;

    return ctx;
}

void KqueueConnectionHandler::ReleaseConnection(ConnectionContext* ctx)
{
    if(!ctx) return;

    numConnectionsAlive_--;

    std::uint32_t idx = ctx - &connections_[0];

    timerWheel_.Cancel(idx);

    if(ctx->isAsyncTimerOperation) {
        if(timerHeap_.Remove(idx))
            UpdateAsyncTimer();
        else
            logger_.Warn("[Kqueue]: Failed to cancel async timer");
    }

    if(ctx->socket > 0)
        close(ctx->socket);

    ipLimiter_.ReleaseConnection(ctx->connInfo);

    ctx->ResetContext();
    FreeSlot(connBitmap_.get(), idx);
}


// =============================================================================
// Helper Functions — Misc
// =============================================================================

std::uint64_t KqueueConnectionHandler::NowMs()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        SteadyClock::now() - startTime_
    ).count();
}

bool KqueueConnectionHandler::SetNonBlocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if(flags < 0) return false;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

bool KqueueConnectionHandler::EnsureFileReady(ConnectionContext* ctx, std::string path)
{
    auto [fd, size] = fileCache_.GetFileDesc(std::move(path));
    if(fd < 0) return false;

    if(!ctx->fileInfo)
        ctx->fileInfo = new FileInfo{};

    ctx->fileInfo->fd       = fd;
    ctx->fileInfo->offset   = 0;
    ctx->fileInfo->fileSize = size;
    return true;
}

bool KqueueConnectionHandler::EnsureReadReady(ConnectionContext* ctx)
{
    auto& rwBuffer = ctx->rwBuffer;
    auto& netCfg   = config_.networkConfig;

    if(rwBuffer.IsReadInitialized()) return true;

    if(!rwBuffer.InitReadBuffer(netCfg.bufferIncrSize)) {
        logger_.Error("[Kqueue]: Failed to init read buffer");
        Close(ctx);
        return false;
    }
    return true;
}

bool KqueueConnectionHandler::ResolveHostToIpv4(const char* host, in_addr* outAddr)
{
    addrinfo hints = {0};
    addrinfo *res = nullptr, *rp = nullptr;
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags    = AI_ADDRCONFIG;

    int ret = getaddrinfo(host, NULL, &hints, &res);
    if(ret != 0) return false;

    bool found = false;
    for(rp = res; rp; rp = rp->ai_next) {
        if(rp->ai_family == AF_INET) {
            *outAddr = reinterpret_cast<sockaddr_in*>(rp->ai_addr)->sin_addr;
            found = true;
            break;
        }
    }
    freeaddrinfo(res);
    return found;
}


// =============================================================================
// Helper Functions — kqueue wrappers
// =============================================================================

void KqueueConnectionHandler::KqAdd(int fd, int16_t filter, void* udata)
{
    struct kevent ev{};
    // EV_CLEAR = edge-triggered (same behaviour as EPOLLET on Linux)
    EV_SET(&ev, fd, filter, EV_ADD | EV_CLEAR, 0, 0, udata);
    if(kevent(kqFd_, &ev, 1, nullptr, 0, nullptr) < 0)
        logger_.Warn("[Kqueue]: KqAdd failed for fd=", fd, ": ", strerror(errno));
}

void KqueueConnectionHandler::KqDel(int fd, int16_t filter)
{
    struct kevent ev{};
    EV_SET(&ev, fd, filter, EV_DELETE, 0, 0, nullptr);
    // Ignore errors — deleting a non-existent filter is harmless
    kevent(kqFd_, &ev, 1, nullptr, 0, nullptr);
}

void KqueueConnectionHandler::KqSetTimer(uintptr_t id, std::uint64_t ms, bool oneShot)
{
    struct kevent ev{};
    // NOTE_MILLISECONDS tells kqueue the data field is in milliseconds.
    // EV_ONESHOT fires once then removes itself; without it the timer repeats.
    unsigned short flags = EV_ADD | (oneShot ? EV_ONESHOT : 0);
    EV_SET(&ev, id, EVFILT_TIMER, flags, 0, (intptr_t)ms, nullptr);
    if(kevent(kqFd_, &ev, 1, nullptr, 0, nullptr) < 0)
        logger_.Warn("[Kqueue]: KqSetTimer failed for id=", id, ": ", strerror(errno));
}

void KqueueConnectionHandler::KqDisarmTimer(uintptr_t id)
{
    struct kevent ev{};
    EV_SET(&ev, id, EVFILT_TIMER, EV_DELETE, 0, 0, nullptr);
    kevent(kqFd_, &ev, 1, nullptr, 0, nullptr);
}

void KqueueConnectionHandler::UpdateAsyncTimer()
{
    TimerNode* min = timerHeap_.GetMin();

    if(!min) {
        KqDisarmTimer(ASYNC_TIMER_ID);
        return;
    }

    std::uint64_t now    = NowMs();
    std::uint64_t expire = min->delay;
    std::uint64_t remain = (expire <= now) ? 1 : (expire - now);

    // One-shot: fires once, then we reschedule from the next PopExpired pass
    KqSetTimer(ASYNC_TIMER_ID, remain, true);
}


// =============================================================================
// I/O Dispatch — Receive / SendFile / ResumeStream
// (Logic identical to epoll; only socket syscall wrappers differ)
// =============================================================================

void KqueueConnectionHandler::Receive(ConnectionContext* ctx)
{
    if(!EnsureReadReady(ctx)) return;

    auto& rwBuffer = ctx->rwBuffer;
    bool  gotData  = false;

    while(true) {
        ValidRegion region = rwBuffer.GetWritableReadRegion();
        if(!region.ptr || region.len == 0) {
            if(!rwBuffer.GrowReadBuffer(config_.networkConfig.bufferIncrSize,
                                        config_.networkConfig.maxRecvBufferSize)) {
                logger_.Warn("[Kqueue]: Read buffer full, closing connection");
                Close(ctx);
                return;
            }
            region = rwBuffer.GetWritableReadRegion();
        }

        ssize_t res = WrapRead(ctx, region.ptr, region.len);
        if(res > 0) {
            rwBuffer.AdvanceReadLength(res);
            gotData = true;
        }
        else if(res == 0) {
            Close(ctx);
            return;
        }
        else {
            if(errno == EAGAIN || errno == EWOULDBLOCK) {
                ctx->eventType = EventType::EVENT_RECV;
                break;
            }
            Close(ctx);
            return;
        }
    }

    if(gotData)
        onReceive_(ctx);
}

void KqueueConnectionHandler::SendFile(ConnectionContext* ctx)
{
    if(!ctx->fileInfo) {
        logger_.Warn("[Kqueue]: SendFile expects ctx->fileInfo to be set, got nullptr");
        ctx->SetConnectionState(ConnectionState::CONNECTION_CLOSE);
        Write(ctx, HttpError::internalError);
        return;
    }

    auto* fileInfo = ctx->fileInfo;

    while(fileInfo->offset < fileInfo->fileSize) {
        ssize_t n = WrapFile(ctx, fileInfo->fd, &fileInfo->offset,
                             fileInfo->fileSize - fileInfo->offset);
        if(n > 0) continue;

        if(n < 0) {
            if(n == SWITCH_FILE_TO_STREAM) { ResumeStream(ctx); return; }
            if(errno == EAGAIN || errno == EWOULDBLOCK)
                ctx->eventType = EventType::EVENT_SEND_FILE;
            else
                Close(ctx);
            return;
        }
        break;
    }

    if(ctx->GetConnectionState() == ConnectionState::CONNECTION_CLOSE)
        Close(ctx);
    else {
        ctx->ClearContext();
        ResumeReceive(ctx);
    }
}

void KqueueConnectionHandler::ResumeStream(ConnectionContext* ctx)
{
    if(!ctx->streamGenerator) {
        logger_.Warn("[Kqueue]: streamGenerator is nullptr");
        Close(ctx);
        return;
    }

    constexpr std::size_t chunkHeaderReserve = 10;
    auto& rwBuffer = ctx->rwBuffer;

    auto writeMeta = rwBuffer.GetWriteMeta();
    if(!writeMeta) { Close(ctx); return; }

    writeMeta->dataLength    = 0;
    writeMeta->writtenLength = 0;

    auto writeRegion = rwBuffer.GetWritableWriteRegion();
    if(!writeRegion.ptr || writeRegion.len == 0) { Close(ctx); return; }

    char*       chunkPtr = !ctx->streamChunked ? writeRegion.ptr : writeRegion.ptr + chunkHeaderReserve;
    std::size_t chunkCap = !ctx->streamChunked ? writeRegion.len : writeRegion.len - chunkHeaderReserve - 2;

    auto streamResult = ctx->streamGenerator({chunkPtr, chunkCap});
    RefreshExpiry(ctx, config_.networkConfig.idleTimeout);

    switch(streamResult.action) {
        case StreamAction::CONTINUE:
        {
            if(streamResult.writtenBytes == 0 || streamResult.writtenBytes > UINT32_MAX) {
                Close(ctx);
                return;
            }

            if(!ctx->streamChunked) {
                writeMeta->dataLength = streamResult.writtenBytes;
                Write(ctx);
                return;
            }

            char   chunkHeader[chunkHeaderReserve + 1] = {0};
            int    headerLen = snprintf(chunkHeader, chunkHeaderReserve, "%zX\r\n", streamResult.writtenBytes);
            if(headerLen <= 0 || headerLen >= (int)chunkHeaderReserve) { Close(ctx); return; }

            writeMeta->dataLength = chunkHeaderReserve + streamResult.writtenBytes + 2;
            std::memcpy(chunkPtr - headerLen, chunkHeader, headerLen);
            rwBuffer.AdvanceWriteLength(chunkHeaderReserve - headerLen);

            char* trailer = chunkPtr + streamResult.writtenBytes;
            *trailer++ = '\r';
            *trailer++ = '\n';
            Write(ctx);
            return;
        }
        case StreamAction::STOP_AND_ALIVE_CONN:
            ctx->SetConnectionState(ConnectionState::CONNECTION_ALIVE);
            break;
        case StreamAction::STOP_AND_CLOSE_CONN:
        default:
            ctx->SetConnectionState(ConnectionState::CONNECTION_CLOSE);
            break;
    }

    bool wasChunked = static_cast<bool>(ctx->streamChunked);

    writeMeta->dataLength    = 0;
    writeMeta->writtenLength = 0;
    ctx->isStreamOperation   = 0;
    ctx->streamChunked       = 0;
    ctx->streamGenerator     = {};

    if(wasChunked)
        rwBuffer.AppendData(CHUNK_END, sizeof(CHUNK_END) - 1)
            ? Write(ctx)
            : Close(ctx);
    else if(ctx->GetConnectionState() == ConnectionState::CONNECTION_ALIVE) {
        ctx->ClearContext();
        ResumeReceive(ctx);
    }
    else Close(ctx);
}


// =============================================================================
// WrapAccept / WrapRead / WrapWrite / WrapFile
// =============================================================================

void KqueueConnectionHandler::WrapAccept(ConnectionContext* ctx)
{
    // Pack (generationId << 32 | slotIndex) into udata — same trick as epoll
    std::uint32_t idx = static_cast<std::uint32_t>(ctx - connections_.get());
    void* udata = reinterpret_cast<void*>(
        (static_cast<std::uint64_t>(ctx->generationId) << 32) | idx
    );

    int clientFd = ctx->socket;

    if(useHttps_) {
        ctx->sslConn = sslHandler_->Wrap(clientFd);
        if(!ctx->sslConn) { Close(ctx); return; }

        SSLReturn hsResult = sslHandler_->Handshake(ctx->sslConn);
        switch(hsResult) {
            case SSLReturn::SUCCESS:
                ctx->eventType = EventType::EVENT_RECV;
                break;
            case SSLReturn::WANT_READ:
            case SSLReturn::WANT_WRITE:
                ctx->eventType = EventType::EVENT_HANDSHAKE;
                break;
            default:
                Close(ctx);
                return;
        }
    }
    else
        ctx->eventType = EventType::EVENT_RECV;

    // Register both read and write filters upfront (EV_CLEAR = edge-triggered)
    // kqueue fires EVFILT_WRITE only when the socket becomes writable;
    // we suppress unwanted write events by checking ctx->eventType in the loop.
    KqAdd(clientFd, EVFILT_READ,  udata);
    KqAdd(clientFd, EVFILT_WRITE, udata);

    RefreshExpiry(ctx, config_.networkConfig.idleTimeout);
}

ssize_t KqueueConnectionHandler::WrapRead(ConnectionContext* ctx, char* buf, std::size_t len)
{
    if(!ctx->sslConn)
        return ::recv(ctx->socket, buf, len, 0);

    SSLResult result = sslHandler_->Read(ctx->sslConn, buf, static_cast<int>(len));
    switch(result.error) {
        case SSLReturn::SUCCESS:    return result.res;
        case SSLReturn::WANT_READ:
        case SSLReturn::WANT_WRITE: errno = EAGAIN; return -1;
        case SSLReturn::CLOSED:     return 0;
        case SSLReturn::SYSCALL:    return -1;
        case SSLReturn::FATAL:
        default:                    errno = EIO; return -1;
    }
}

ssize_t KqueueConnectionHandler::WrapWrite(ConnectionContext* ctx, const char* buf, std::size_t len)
{
    if(!ctx->sslConn)
        return ::send(ctx->socket, buf, len, 0); // MSG_NOSIGNAL doesn't exist on macOS; use SO_NOSIGPIPE

    SSLResult result = sslHandler_->Write(ctx->sslConn, buf, static_cast<int>(len));
    switch(result.error) {
        case SSLReturn::SUCCESS:    return result.res;
        case SSLReturn::WANT_READ:
        case SSLReturn::WANT_WRITE: errno = EAGAIN; return -1;
        case SSLReturn::CLOSED:     return 0;
        case SSLReturn::SYSCALL:    return -1;
        case SSLReturn::FATAL:
        default:                    errno = EIO; return -1;
    }
}

ssize_t KqueueConnectionHandler::WrapFile(ConnectionContext* ctx, int fd, off_t* offset, std::size_t count)
{
    if(!ctx->sslConn) {
        // macOS sendfile signature:
        //   int sendfile(int fd, int s, off_t offset, off_t *len, struct sf_hdtr*, int flags)
        //   *len = bytes to send (in), bytes actually sent (out)
        //   returns 0 on full send, -1 on error (EAGAIN = partial)
        off_t len = static_cast<off_t>(count);
        int   ret = ::sendfile(fd, ctx->socket, offset ? *offset : 0, &len, nullptr, 0);

        if(len > 0 && offset)
            *offset += len; // advance offset by what was actually sent

        if(ret == 0)
            return len > 0 ? len : 0; // full send
        // ret == -1
        if(errno == EAGAIN || errno == EWOULDBLOCK)
            return -1; // partial; errno already set
        return -1;     // fatal
    }

    // SSL path: same streaming fallback as epoll
    SSLResult result = sslHandler_->WriteFile(ctx->sslConn, fd, offset ? *offset : 0, count);
    switch(result.error) {
        case SSLReturn::NO_IMPL:
            // Switch to streaming mode (identical to epoll)
            ctx->isFileOperation   = 0;
            ctx->isStreamOperation = 1;
            ctx->streamChunked     = 0;
            ctx->streamGenerator   = [fileInfo = ctx->fileInfo](StreamBuffer buffer) {
                std::int64_t res = pread(fileInfo->fd, buffer.buffer, buffer.size, fileInfo->offset);
                if(res <= 0)
                    return StreamResult{0, res == 0
                        ? StreamAction::STOP_AND_ALIVE_CONN
                        : StreamAction::STOP_AND_CLOSE_CONN};
                fileInfo->offset += res;
                return StreamResult{static_cast<std::size_t>(res), StreamAction::CONTINUE};
            };
            return SWITCH_FILE_TO_STREAM;

        case SSLReturn::SUCCESS:
            if(offset) *offset += result.res;
            return result.res;
        case SSLReturn::WANT_READ:
        case SSLReturn::WANT_WRITE: errno = EAGAIN; return -1;
        case SSLReturn::CLOSED:     return 0;
        case SSLReturn::SYSCALL:    return -1;
        case SSLReturn::FATAL:
        default:                    errno = EIO; return -1;
    }
}

} // namespace WFX::OSSpecific

#endif // __APPLE__