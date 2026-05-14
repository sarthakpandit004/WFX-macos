#ifndef WFX_MACOS_KQUEUE_CONNECTION_HPP
#define WFX_MACOS_KQUEUE_CONNECTION_HPP

// Only compile this file on macOS / BSD
#if defined(__APPLE__)

#include "config/config.hpp"
#include "http/connection/http_connection.hpp"
#include "http/limits/ip_limiter/ip_limiter.hpp"
#include "http/ssl/http_ssl.hpp"
#include "utils/fileops/filecache.hpp"
#include "utils/pool/bitmap_pool.hpp"
#include "utils/timer/timer_wheel.hpp"
#include "utils/timer/timer_heap.hpp"

#include <sys/event.h>   // kqueue, kevent, EV_SET, EVFILT_READ, EVFILT_WRITE, EVFILT_TIMER
#include <sys/types.h>
#include <atomic>

namespace WFX::OSSpecific {

using namespace WFX::Http;  // HttpConnectionHandler, ReceiveCallback, ConnectionContext, ...
using namespace WFX::Utils; // Logger, RWBuffer, ...
using namespace WFX::Core;  // Config

using SteadyClock = std::chrono::steady_clock;

// ---------------------------------------------------------------------------
// Identifiers used for kqueue EVFILT_TIMER events.
// kqueue timers are identified by an arbitrary integer (ev.ident), not by
// a file descriptor like Linux timerfd. We pick two constants that will
// never collide with real file descriptor numbers (which start at 0).
// ---------------------------------------------------------------------------
static constexpr uintptr_t TIMEOUT_TIMER_ID = 0xFFFF'0001u; // drives the TimerWheel (connection timeouts)
static constexpr uintptr_t ASYNC_TIMER_ID   = 0xFFFF'0002u; // drives the TimerHeap  (async delays)

using ConnectionPool    = BitmapPool<ConnectionContext>;
using EndpointContainer = std::pair<EndpointContext, ConnectionPool>;
using EndpointPool      = std::vector<EndpointContainer>;

class KqueueConnectionHandler : public HttpConnectionHandler {
public:
    KqueueConnectionHandler(bool useHttps);
    ~KqueueConnectionHandler();

public: // Initializing
    void Initialize(const std::string& host, std::uint16_t port)                                   override;
    std::uint16_t AllocateEndpoint(
    std::string_view host, std::string_view port, std::uint32_t cLimit, std::uint32_t ifLimit, bool useTLS
) override;
    void SetEngineCallback(ReceiveCallback onData)                                      override;

public: // I/O Operations
    void ResumeReceive(ConnectionContext* ctx)                                         override;
    Shared::EndpointStatus WriteEndpoint(
    ConnectionContext* ctx, std::uint32_t endpointIndex, const std::byte* ptr, std::uint32_t size
) override;
    void Write(ConnectionContext* ctx, std::string_view buffer = {})                   override;
    void WriteFile(ConnectionContext* ctx, std::string path)                           override;
    void Stream(ConnectionContext* ctx, Shared::StreamGenerator generator, bool streamChunked = true)  override;
    void Close(ConnectionContext* ctx, bool forceClose = false)                        override;

public: // Main Functions
    void Run()                                                                         override;
    void RefreshExpiry(ConnectionContext* ctx, std::uint16_t timeoutSeconds)           override;
    bool RefreshAsyncTimer(ConnectionContext* ctx, std::uint32_t delayMilliseconds, Shared::AsyncData asyncData)    override;
    void Stop()                                                                        override;

private: // Helper Functions — connection pool (identical logic to epoll)
    std::int64_t       AllocSlot(std::uint64_t* bitmap, std::uint32_t numWords);
    void               FreeSlot(std::uint64_t* bitmap, std::uint32_t idx);
    constexpr static std::uint16_t CLIENT_CONNECTION_TAG = 0xFFFF;
    ConnectionContext* GetConnection(std::uint16_t endpointIndex = CLIENT_CONNECTION_TAG);
    void               ReleaseConnection(ConnectionContext* ctx, bool isEndpoint = false);

    // Misc helpers
    std::uint64_t      NowMs();
    bool               SetNonBlocking(int fd);
    bool               EnsureFileReady(ConnectionContext* ctx, std::string path);
    bool               EnsureReadReady(ConnectionContext* ctx);
    bool               ResolveHost(const char* host, const char* port, sockaddr_storage* outAddr, socklen_t* outLen);

    // I/O dispatch
    void               Receive(ConnectionContext* ctx);
    void               SendFile(ConnectionContext* ctx);
    void               ResumeStream(ConnectionContext* ctx);
    void               UpdateAsyncTimer();

    void               HandleAsyncCallback(ConnectionContext* ctx, Shared::AsyncResult res, bool destroy);

    // kqueue wrappers — changes are batched into changeList_ and flushed
    // in bulk via FlushChanges() to minimise kevent() syscall overhead.
    void               KqAdd(int fd, int16_t filter, void* udata);        // queues EV_ADD | EV_CLEAR
    void               KqDel(int fd, int16_t filter);                      // queues EV_DELETE
    void               FlushChanges();                                      // submits pending changelist
    void               KqSetTimer(uintptr_t id, std::uint64_t ms, bool oneShot); // EVFILT_TIMER
    void               KqDisarmTimer(uintptr_t id);

    // Accept / read / write / sendfile wrappers (handle SSL transparently)
    void               WrapAccept(ConnectionContext* ctx);
    ssize_t            WrapRead(ConnectionContext* ctx, char* buf, std::size_t len);
    ssize_t            WrapWrite(ConnectionContext* ctx, const char* buf, std::size_t len);
    ssize_t            WrapFile(ConnectionContext* ctx, int fd, off_t* offset, std::size_t count);

private: // Singletons
    Config&            config_     = Config::GetInstance();
    Logger&            logger_     = Logger::GetInstance();
    FileCache&         fileCache_  = FileCache::GetInstance();
    BufferPool&        pool_       = BufferPool::GetInstance();

    IpLimiter          ipLimiter_         = {pool_};
    ReceiveCallback    onReceive_         = {};
    
    std::atomic<bool>  running_           = true;
    bool               useHttps_          = false;

private: // Constants
    constexpr static char    CHUNK_END[]           = "0\r\n\r\n";
    constexpr static ssize_t SWITCH_FILE_TO_STREAM = std::numeric_limits<ssize_t>::min();
    constexpr static std::uint16_t MAX_DISTINCT_ENDPOINTS = 0xFFFE;
    // How often to tick the timeout wheel (seconds)
    constexpr static int INVOKE_TIMEOUT_COOLDOWN = 5;
    constexpr static int INVOKE_TIMEOUT_DELAY    = 1;
    // Changelist batch size — tune upward if you have very write-heavy workloads
    constexpr static int MAX_CHANGE_BATCH        = 64;

private: // Timeout / async timers
    EndpointPool            endpoints_  = {};
    TimerWheel              timerWheel_;
    TimerHeap               timerHeap_;
    SteadyClock::time_point startTime_  = SteadyClock::now();

private: // kqueue + listen socket
    int           listenFd_  = -1;
    int           kqFd_      = -1;   // the kqueue descriptor (replaces epollFd_)
    std::uint16_t maxEvents_ = config_.osSpecificConfig.maxEvents;

    std::unique_ptr<HttpWFXSSL>      sslHandler_ = nullptr;
    std::unique_ptr<struct kevent[]> events_      = nullptr; // event buffer for kevent() output

    // Pending changelist — flushed to kqueue in batches
    struct kevent changeList_[MAX_CHANGE_BATCH];
    int           changeCount_ = 0;

private: // Connection pool (same bitmap design as epoll)
    ConnectionPool connections_ = {config_.networkConfig.maxConnections};
    std::uint32_t  connSlots_     = 0;
    std::uint32_t  connLastIndex_ = 0;
    std::uint64_t abortedCount_ = 0;
    std::uint64_t fdExhaustedCount_ = 0;
    // TODO: FOR DEBUG ONLY, REMOVE AFTER
    std::uint64_t numConnectionsAlive_ = 0;
   
};

} // namespace WFX::OSSpecific

#endif // __APPLE__
#endif // WFX_MACOS_KQUEUE_CONNECTION_HPP