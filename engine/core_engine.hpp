#ifndef WFX_CORE_ENGINE_HPP
#define WFX_CORE_ENGINE_HPP

#include "config/config.hpp"
#include "http/connection/http_connection_factory.hpp"
#include "http/middleware/http_middleware.hpp"
#include "http/routing/router.hpp"

#include <memory>
#include <string>

namespace WFX::Core {

class CoreEngine {
public:
    // Full constructor — loads the DLL, registers routes, loads middleware.
    // Call this ONCE (for engine 0 / the main thread).
    CoreEngine(const char* dllPath, bool useHttps);

    // Worker constructor — skips DLL loading entirely.
    // All worker engines share the same pre-populated Router and Middleware
    // from engine 0, so RegisterMasterAPI is never called more than once.
    //
    // Root cause of the 404 bug:
    //   dlopen() with RTLD_GLOBAL is reference-counted — it returns the same
    //   handle on every subsequent call for the same path.  RegisterMasterAPI
    //   inside the user DLL has a static-local "registered" guard, so every
    //   call after the first returns immediately without registering anything.
    //   Engines 1..N end up with empty routers → every request is a 404.
    //
    //   Sharing engine 0's router via shared_ptr sidesteps this entirely:
    //   routes are registered exactly once, and all engines read the same
    //   immutable trie concurrently (safe — read-only after Listen() starts).
    CoreEngine(std::shared_ptr<Http::Router>         sharedRouter,
               std::shared_ptr<Http::HttpMiddleware>  sharedMiddleware,
               bool                                   useHttps);

    void Listen(const std::string& host, std::uint16_t port);
    void Stop();

public:
    // Accessors so run.cpp can extract the shared_ptrs after engine 0 is built.
    std::shared_ptr<Http::Router>         GetRouter()     { return router_; }
    std::shared_ptr<Http::HttpMiddleware>  GetMiddleware() { return middleware_; }

public: // Static stuff
    static void OnCoroutineComplete(void* ud, Shared::AsyncResult result);

private: // Internal Functions
    void HandleRequest(Http::ConnectionContext* ctx);
    void HandleResponse(Http::ConnectionContext* ctx);
    void HandleSuccess(Http::ConnectionContext* ctx);

private: // Helper Functions
    void         FinishRequest(Http::ConnectionContext* ctx);
    void         HandleError(Http::ConnectionContext* ctx, Shared::HttpStatus code, std::string_view message);
    std::uint8_t HandleConnectionHeader(std::string_view header);
    void         HandleUserDLLInjection(const char* dllDir);
    void         HandleMiddlewareLoading();

private:
    Config&        config_ = Config::GetInstance();
    Utils::Logger& logger_ = Utils::Logger::GetInstance();

    // shared_ptr so the populated router and middleware built by engine 0 can
    // be handed to worker engines without copying or re-registering routes.
    std::shared_ptr<Http::Router>         router_;
    std::shared_ptr<Http::HttpMiddleware>  middleware_;

    std::unique_ptr<Http::HttpConnectionHandler> connHandler_;
};

} // namespace WFX

#endif // WFX_CORE_ENGINE_HPP