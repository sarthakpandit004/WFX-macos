#if defined(__APPLE__)
#include <poll.h>
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
#include "shared/apis/http_api.hpp"

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

#ifdef WFX_DEBUG_LOGGING
    logger_.Info("[Kqueue]: Cleaned up resources successfully");
#endif
}


// =============================================================================
// Initializing
// =============================================================================

void KqueueConnectionHandler::Initialize(const std::string& host, std::uint16_t port)
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
    

    
  
    events_      = std::make_unique<struct kevent[]>(maxEvents_);
    connections_ = ConnectionPool(connSlots_);
  

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
    sockaddr_storage addr{};
    socklen_t        addrLen = 0;
    std::string      portStr = std::to_string(port);
    if(!ResolveHost(host.c_str(), portStr.c_str(), &addr, &addrLen))
        logger_.Fatal("[Kqueue]: Failed to resolve host '", host, '\'');
    if(bind(listenFd_, (sockaddr*)&addr, addrLen) < 0)
        logger_.Fatal("[Kqueue]: Failed to bind socket: ", strerror(errno));
    if(listen(listenFd_, osConfig.backlog) < 0)
        logger_.Fatal("[Kqueue]: Failed to listen: ", strerror(errno));

    // ---- Create kqueue ----
    kqFd_ = kqueue();
    if(kqFd_ < 0)
        logger_.Fatal("[Kqueue]: Failed to create kqueue: ", strerror(errno));

    // Watch listen socket for incoming connections (EVFILT_READ)
    KqAdd(listenFd_, EVFILT_READ, nullptr); // nullptr udata = special fd, not a connection
    FlushChanges();

    // ---- Timeout timer (drives TimerWheel, fires every INVOKE_TIMEOUT_COOLDOWN seconds) ----
    timerWheel_.Init(
        connSlots_,
        1024, 1, TimeUnit::SECONDS,
        [this](std::uint32_t connId, std::uint32_t) {
            ConnectionContext* ctx = connections_.GetPtr(connId);
            // FIX: was || ctx->IsAsyncOperation() — that closed connections
            // mid-async-op and caused non-2xx responses.
            if(
                ctx->GetConnectionState() != ConnectionState::CONNECTION_CLOSE
                && !ctx->IsAsyncOperation()
            )
                Close(ctx, true);
        }
    );

    // EVFILT_TIMER: ident=TIMEOUT_TIMER_ID, period in milliseconds
    // This fires every INVOKE_TIMEOUT_DELAY * 1000 ms and is NOT one-shot.
    KqSetTimer(TIMEOUT_TIMER_ID, INVOKE_TIMEOUT_DELAY * 1000, false);

    // ---- Async timer placeholder ----
    // The async timer is one-shot and gets rescheduled by UpdateAsyncTimer().
    // We don't arm it here; UpdateAsyncTimer() will arm it when needed.
}

void KqueueConnectionHandler::SetEngineCallback(ReceiveCallback onData)
{
    onReceive_         = std::move(onData);
    
}


// =============================================================================
// I/O Operations  (logic identical to epoll; only the "re-arm" calls differ)
// =============================================================================

void KqueueConnectionHandler::ResumeReceive(ConnectionContext* ctx)
{
    if(!EnsureReadReady(ctx))
        return;
    ctx->eventType = EventType::EVENT_RECV;
    struct kevent ev{};
    void* udata = reinterpret_cast<void*>(
        (static_cast<std::uint64_t>(ctx->generationId) << 32) |
        connections_.GetIndex(ctx)
    );
    EV_SET(&ev, ctx->socket, EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0, udata);
    if(kevent(kqFd_, &ev, 1, nullptr, 0, nullptr) < 0)
        logger_.Warn("[Kqueue]: ResumeReceive failed fd=", ctx->socket);
}

void KqueueConnectionHandler::Write(ConnectionContext* ctx, std::string_view msg)
{
    // Case 1: fire-and-forget direct send (error codes, 100-Continue, etc.)
    //
    // FIX: The original cast the return value of WrapWrite to void and jumped
    // straight to __CleanupOrRearm. Under high load the kernel send buffer can
    // be full: send() returns EAGAIN or writes fewer bytes than requested and
    // the response is silently truncated — the peer gets a partial HTTP
    // response and reports a read error. We now loop until the full message is
    // sent and close the connection on any unrecoverable failure, matching the
    // behaviour of Case 2 below.
   if(!msg.empty()) {
    ssize_t n = WrapWrite(ctx, msg.data(), msg.size());
    if(n != static_cast<ssize_t>(msg.size())) {
        Close(ctx);
        return;
    }
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

            if(n > 0) {
                writeMeta->writtenLength += n;
            }
            else if(n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                KqAdd(ctx->socket, EVFILT_WRITE,
                    reinterpret_cast<void*>(
                        (static_cast<std::uint64_t>(ctx->generationId) << 32) |
                        connections_.GetIndex(ctx)
                    )
                );
                FlushChanges();
                ctx->isPendingWriteEvent = 1;
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
    if(ctx->streamGenerator.ctx && ctx->streamGenerator.Next) { ResumeStream(ctx); return; }
    if(ctx->isFileOperation)  { SendFile(ctx);     return; }
    if(ctx->GetConnectionState() == ConnectionState::CONNECTION_CLOSE)
        Close(ctx);
    else {
    ctx->ClearContext();

    RefreshExpiry(
        ctx,
        config_.networkConfig.idleTimeout
    );

    if(ctx->isPendingWriteEvent)
{
    KqDel(ctx->socket, EVFILT_WRITE);
    FlushChanges();
    ctx->isPendingWriteEvent = 0;
}

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

void KqueueConnectionHandler::Stream(ConnectionContext* ctx, Shared::StreamGenerator generator, bool streamChunked)
{
    if(!generator.ctx || !generator.Next) {
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
    FlushChanges();
    ReleaseConnection(ctx);
}


// =============================================================================
// Main Event Loop
// =============================================================================

void KqueueConnectionHandler::Run()
{
    if(!onReceive_)
        logger_.Fatal(
            "[Kqueue]: 'onReceive_' or 'onAsyncCompletion_' not initialised."
            " Call SetEngineCallback before Run."
        );
       

    while(running_) {
        // Flush any pending kqueue changes before blocking
        FlushChanges();

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
                    continue;
                }

                if(ev.ident == ASYNC_TIMER_ID) {
                    std::uint64_t newTick = NowMs();
                    std::uint64_t connId  = 0;

                    while(timerHeap_.PopExpired(newTick, connId)) {
                        ConnectionContext* ctx = connections_.GetPtr(connId);
                        ctx->isAsyncTimerOperation = 0;

                        HandleAsyncCallback(ctx, {
                        nullptr, 0,
                        Shared::MiddlewareAction::CONTINUE,
                        Shared::AsyncStatus::COMPLETED
                    }, false);
                    }

                    // Async timer is one-shot; rearm for the next pending entry
                    UpdateAsyncTimer();
                    continue;
                }

                continue; // Unknown timer id — ignore
            }

            // ----------------------------------------------------------------
            // Listen socket — accept new connections
            // ----------------------------------------------------------------
            if((int)ev.ident == listenFd_) {
                while(true) {
                    sockaddr_storage clientAddr{};
                    socklen_t addrLen = sizeof(clientAddr);

                    // macOS does not have accept4(); use accept() + fcntl()
                    int clientFd = accept(listenFd_, (sockaddr*)&clientAddr, &addrLen);
                        if(clientFd < 0) {
                            if(errno == EAGAIN || errno == EWOULDBLOCK) break;
                            if(errno == ECONNABORTED) { abortedCount_++; continue; }
                            if(errno == EMFILE || errno == ENFILE) { fdExhaustedCount_++; continue; }
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
                        tmpIp.type = AF_INET;
                    }
                    else if(sa->sa_family == AF_INET6) {
                        tmpIp.ip.v6  = reinterpret_cast<sockaddr_in6*>(sa)->sin6_addr;
                        tmpIp.type = AF_INET6;
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
            ConnectionContext* ctx = connections_.GetPtr(idx);
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
                        FlushChanges();
                        ReleaseConnection(ctx);
                        break;
                }
                continue;
            }

            // FIX: EV_EOF — kqueue may deliver remaining readable bytes
            // alongside EV_EOF. Drain them first so the kernel completes the
            // FIN handshake cleanly instead of sending RST (which shows up as
            // "Socket errors: read" in wrk).
            if(ev.flags & EV_EOF) {
                if(ctx->eventType == EventType::EVENT_SEND ||
                ctx->eventType == EventType::EVENT_SEND_FILE)
                {
                    ctx->SetConnectionState(ConnectionState::CONNECTION_CLOSE);
                    if(ev.filter == EVFILT_WRITE)
                        Write(ctx, {});
                    continue;
                }

                if(ctx->eventType == EventType::EVENT_SHUTDOWN) {
                    Close(ctx, true);
                    continue;
                }

                if(ev.filter == EVFILT_READ &&
                ev.data > 0 &&
                ctx->eventType == EventType::EVENT_RECV)
                {
                    Receive(ctx);
                }
                else {
                    Close(ctx, true);
                }
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
                else
                    continue;
            }
        }
    }
}

void KqueueConnectionHandler::RefreshExpiry(ConnectionContext* ctx, std::uint16_t timeoutSeconds)
{
    std::uint32_t idx = connections_.GetIndex(ctx);
    timerWheel_.Schedule(idx, 0, timeoutSeconds);
}

bool KqueueConnectionHandler::RefreshAsyncTimer(ConnectionContext* ctx, std::uint32_t delayMilliseconds, Shared::AsyncData asyncData)
{
    std::uint32_t idx    = connections_.GetIndex(ctx);
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

ConnectionContext* KqueueConnectionHandler::GetConnection(std::uint16_t endpointIndex)
{
    ConnectionContext* ctx = nullptr;
    if(endpointIndex == CLIENT_CONNECTION_TAG)
        ctx = connections_.AllocSlot();
    else
        ctx = endpoints_[endpointIndex].second.AllocSlot();
    if(!ctx)
        return nullptr;
    ctx->generationId++;
    if(ctx->generationId == 0)
        ctx->generationId = 1;
    return ctx;
}


void KqueueConnectionHandler::ReleaseConnection(ConnectionContext* ctx, bool isEndpoint)
{
    if(!ctx) return;

    // Guard against double-release (see Bug 2)
    if(ctx->isReleasing) return;
    ctx->isReleasing = 1;

    numConnectionsAlive_--;

    std::uint32_t idx = connections_.GetIndex(ctx);
    timerWheel_.Cancel(idx);

    if(ctx->isAsyncTimerOperation) {
        if(!timerHeap_.Remove(idx))
            logger_.Warn("[Kqueue]: Failed to cancel async timer");
        else
            UpdateAsyncTimer();
    }

    if(ctx->socket > 0)
{
    struct kevent evs[2];

    EV_SET(&evs[0], ctx->socket, EVFILT_READ, EV_DELETE, 0, 0, nullptr);
    EV_SET(&evs[1], ctx->socket, EVFILT_WRITE, EV_DELETE, 0, 0, nullptr);

    kevent(kqFd_, evs, 2, nullptr, 0, nullptr);

    ::shutdown(ctx->socket, SHUT_RDWR);
    ::close(ctx->socket);

    ctx->socket = -1;
}


    ipLimiter_.ReleaseConnection(ctx->connInfo);

    ipLimiter_.ReleaseConnection(ctx->connInfo);

ctx->socket = -1;

ctx->ResetContext();

    ctx->ResetContext();
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

    ctx->fileInfo.fd       = fd;
    ctx->fileInfo.offset   = 0;
    ctx->fileInfo.fileSize = size;
    return true;
}

bool KqueueConnectionHandler::EnsureReadReady(ConnectionContext* ctx)
{
    auto& rwBuffer = ctx->rwBuffer;
    auto& netCfg   = config_.networkConfig;

    if(rwBuffer.IsReadInitialized()) return true;

    if(!rwBuffer.InitReadBuffer(netCfg.readBufferIncSize)) {
        logger_.Error("[Kqueue]: Failed to init read buffer");
        Close(ctx);
        return false;
    }
    return true;
}

bool KqueueConnectionHandler::ResolveHost(const char* host, const char* port, sockaddr_storage* outAddr, socklen_t* outLen)
{
    addrinfo  hints = {0};
    addrinfo* res   = nullptr;
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags    = AI_ADDRCONFIG;
    int ret = getaddrinfo(host, port, &hints, &res);
    if(ret != 0)
        return false;
    bool found = false;
    if(res != nullptr) {
        if(res->ai_addrlen <= sizeof(sockaddr_storage)) {
            memcpy(outAddr, res->ai_addr, res->ai_addrlen);
            if(outLen)
                *outLen = res->ai_addrlen;
            found = true;
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
    // Buffer into changelist_ — flushed in batches via FlushChanges()
    if(changeCount_ >= MAX_CHANGE_BATCH) FlushChanges();
    EV_SET(&changeList_[changeCount_++], fd, filter, EV_ADD | EV_CLEAR, 0, 0, udata);
}

void KqueueConnectionHandler::KqDel(int fd, int16_t filter)
{
    if(changeCount_ >= MAX_CHANGE_BATCH) FlushChanges();
    EV_SET(&changeList_[changeCount_++], fd, filter, EV_DELETE, 0, 0, nullptr);
}

void KqueueConnectionHandler::FlushChanges()
{
    if(changeCount_ == 0) return;
    // Ignore errors — deleting a non-existent filter is harmless
    kevent(kqFd_, changeList_, changeCount_, nullptr, 0, nullptr);
    changeCount_ = 0;
}

void KqueueConnectionHandler::KqSetTimer(uintptr_t id, std::uint64_t ms, bool oneShot)
{
    struct kevent ev{};
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
            if(!rwBuffer.GrowReadBuffer(config_.networkConfig.readBufferIncSize,
                                        config_.networkConfig.maxReadBufferSize)) {
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
            ctx->SetConnectionState(ConnectionState::CONNECTION_CLOSE);
            Close(ctx, false);
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
    if(ctx->fileInfo.fd < 0) {
        logger_.Warn("[Kqueue]: SendFile expects ctx->fileInfo to be set, got nullptr");
        ctx->SetConnectionState(ConnectionState::CONNECTION_CLOSE);
        Write(ctx, HttpError::internalError);
        return;
    }

    auto& fileInfo = ctx->fileInfo;

    while(fileInfo.offset < fileInfo.fileSize) {
        ssize_t n = WrapFile(ctx, fileInfo.fd, &fileInfo.offset,
                             fileInfo.fileSize - fileInfo.offset);
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
    if(!ctx->streamGenerator.ctx || !ctx->streamGenerator.Next) {
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

    auto streamResult = ctx->streamGenerator.Next(ctx->streamGenerator.ctx, {chunkPtr, chunkCap});
    RefreshExpiry(ctx, config_.networkConfig.idleTimeout);

    switch(streamResult.action) {
        case Shared::StreamAction::CONTINUE:
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
        case Shared::StreamAction::STOP_AND_ALIVE_CONN:
            ctx->SetConnectionState(ConnectionState::CONNECTION_ALIVE);
            break;
        case Shared::StreamAction::STOP_AND_CLOSE_CONN:
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
        rwBuffer.AppendWriteData(CHUNK_END, sizeof(CHUNK_END) - 1, config_.networkConfig.sendBufferIncSize, config_.networkConfig.maxSendBufferSize)
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
    std::uint32_t idx = connections_.GetIndex(ctx);
    void* udata = reinterpret_cast<void*>(
        (static_cast<std::uint64_t>(ctx->generationId) << 32) | idx
    );

    int clientFd = ctx->socket;

    // macOS has no MSG_NOSIGNAL per-send flag. Set SO_NOSIGPIPE on the fd so
    // that writing to a peer-closed socket returns EPIPE (handled) rather than
    // raising SIGPIPE, which would kill the process.
    {
        int noSigPipe = 1;
        if(setsockopt(clientFd, SOL_SOCKET, SO_NOSIGPIPE, &noSigPipe, sizeof(noSigPipe)) < 0)
            logger_.Warn("[Kqueue]: Failed to set SO_NOSIGPIPE on fd=", clientFd, ": ", strerror(errno));
    }

    // FIX: Disable Nagle's algorithm on each accepted socket.
    //
    // Without TCP_NODELAY, the kernel may hold small writes (e.g. 100-Continue
    // or short error responses) for up to 40 ms waiting to coalesce them. At
    // 277k req/s this delay cascades — connections stall, the timeout wheel
    // fires, the server closes with unread data in the buffer, and the kernel
    // sends RST. TCP_NODELAY flushes every write immediately, which eliminates
    // that source of RST-induced read errors entirely.
    {
        int nodelay = 1;
        setsockopt(clientFd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));
        // Non-fatal: if this fails the connection still works, just with Nagle.
    }

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

    KqAdd(clientFd, EVFILT_READ, udata);

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
    {
        ssize_t total_sent = 0;

        while(total_sent < (ssize_t)len)
        {
            ssize_t sent = ::send(
                ctx->socket,
                buf + total_sent,
                len - total_sent,
                0
            );

            if(sent > 0)
            {
                total_sent += sent;
                continue;
            }

            if(sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            {
                if(total_sent > 0)
                    return total_sent;

                return -1;
            }

            return -1;
        }

        return total_sent;
    }

    SSLResult result = sslHandler_->Write(ctx->sslConn, buf, static_cast<int>(len));

    switch(result.error)
    {
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
            ctx->streamGenerator = {
    &ctx->fileInfo,
    [](void* c, Shared::StreamBuffer buffer) -> Shared::StreamResult {
        auto* fi = static_cast<FileInfo*>(c);
        ssize_t res = pread(fi->fd, buffer.buffer, buffer.size, fi->offset);
        if(res <= 0)
            return Shared::StreamResult{0, res == 0
                ? Shared::StreamAction::STOP_AND_ALIVE_CONN
                : Shared::StreamAction::STOP_AND_CLOSE_CONN};
        fi->offset += res;
        return Shared::StreamResult{static_cast<std::size_t>(res), Shared::StreamAction::CONTINUE};
    },
    nullptr
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



// =============================================================================
// HandleAsyncCallback
// =============================================================================
void KqueueConnectionHandler::HandleAsyncCallback(ConnectionContext* ctx, Shared::AsyncResult res, bool destroy)
{
    auto& async = ctx->asyncData;
    if(!async.AsyncComplete && !async.AsyncDestroy)
        return;
    auto complete       = async.AsyncComplete;
    auto kill           = async.AsyncDestroy;
    auto ud             = async.userData;
    async.AsyncComplete = nullptr;
    async.AsyncDestroy  = nullptr;
    async.userData      = nullptr;
    Shared::GetHttpAPIV1()->SetGlobalPtrData(ctx);
    if(destroy) {
        if(kill) kill(ud);
    }
    else {
        if(complete) complete(ud, res);
    }
    Shared::GetHttpAPIV1()->SetGlobalPtrData(nullptr);
}

// =============================================================================
// AllocateEndpoint / WriteEndpoint
// =============================================================================
std::uint16_t KqueueConnectionHandler::AllocateEndpoint(
    std::string_view host, std::string_view port, std::uint32_t cLimit, std::uint32_t ifLimit, bool useTLS
) {
    (void)ifLimit;
    if(endpoints_.size() > MAX_DISTINCT_ENDPOINTS)
        logger_.Fatal("[Kqueue]: Too many distinct domain endpoints registered");

    auto& endpointSlot = endpoints_.emplace_back(
        std::piecewise_construct,
        std::forward_as_tuple(),
        std::forward_as_tuple(cLimit)
    );
    auto& endpointInfo = endpointSlot.first;
    auto& endpointPool = endpointSlot.second;
    std::uint16_t endpointIdx = endpoints_.size() - 1;

    for(std::uint32_t j = 0; j < endpointPool.GetSlots(); j++) {
        auto* ctx = endpointPool.GetPtr(j);
        ctx->endpointIdx = endpointIdx;
        ctx->SetConnectionState(ConnectionState::CONNECTION_CLOSE);
        ctx->SetEndpointState(
            useTLS ? EndpointState::ENDPOINT_SECURE : EndpointState::ENDPOINT_INSECURE
        );
    }
    std::string tempHost = std::string(host);
    std::string tempPort = std::string(port);
    if(!ResolveHost(tempHost.c_str(), tempPort.c_str(), &endpointInfo.addr, &endpointInfo.addrLen))
        logger_.Fatal("[Kqueue]: Failed to resolve endpoint URL: ", host, ':', port);
    endpointInfo.host = std::move(tempHost);
    return endpointIdx;
}

Shared::EndpointStatus KqueueConnectionHandler::WriteEndpoint(
    ConnectionContext* ctx, std::uint32_t endpointIndex, const std::byte* ptr, std::uint32_t size
) {
    if(endpointIndex > endpoints_.size() - 1)
        return Shared::EndpointStatus::INVALID_KEY;
    auto* allocatedCtx = GetConnection(static_cast<std::uint16_t>(endpointIndex));
    if(!allocatedCtx)
        return Shared::EndpointStatus::POOL_EXHAUSTED;
    numConnectionsAlive_++;
    auto& endpointRWBuffer = allocatedCtx->rwBuffer;
    if(
        !endpointRWBuffer.IsWriteInitialized()
        && !endpointRWBuffer.InitWriteBuffer(config_.networkConfig.maxSendBufferSize)
    ) {
        ReleaseConnection(allocatedCtx, true);
        return Shared::EndpointStatus::BUFFER_ERROR;
    }
    if(!endpointRWBuffer.AppendWriteData(reinterpret_cast<const char*>(ptr), size, config_.networkConfig.sendBufferIncSize, config_.networkConfig.maxSendBufferSize)) {
        ReleaseConnection(allocatedCtx, true);
        return Shared::EndpointStatus::BUFFER_ERROR;
    }
    return Shared::EndpointStatus::SUCCESS;
}

} // namespace WFX::OSSpecific
#endif // __APPLE__