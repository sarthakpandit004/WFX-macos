#include "core_engine.hpp"
#include "http/response.hpp"
#include "http/request.hpp"
#include "http/response/http_response.hpp"
#include "http/request/http_request.hpp"
#include "http/connection/http_connection.hpp"
#include "http/common/http_error_msgs.hpp"
#include "http/common/http_global_state.hpp"
#include "http/parser/http_parser.hpp"
#include "shared/apis/master_api.hpp"
#include "utils/backport/string.hpp"
#include "utils/fileops/filesystem.hpp"
#include "utils/process/process.hpp"
#include "utils/crash_tracer/crash_tracer.hpp"

#if defined(__linux__) || defined(__APPLE__)
    #include <dlfcn.h>
#endif

namespace WFX::Core {

using namespace WFX::Http;
using namespace WFX::Shared;
using namespace WFX::Utils;

// Each worker thread sets this at the top of Listen() so OnCoroutineComplete()
// can find the right engine without touching any shared global state.
static thread_local CoreEngine* tl_currentEngine = nullptr;

enum ConnectionHeader : std::uint8_t {
    NONE       = 0,
    CLOSE      = 1 << 0,
    KEEP_ALIVE = 1 << 1,
    UPGRADE    = 1 << 2,
    ERROR      = 1 << 3,
};

// ---------------------------------------------------------------------------
// Full constructor (engine 0 only)
// Allocates fresh Router + Middleware, loads the DLL, registers routes.
// ---------------------------------------------------------------------------
CoreEngine::CoreEngine(const char* dllPath, bool useHttps)
    : router_    (std::make_shared<Http::Router>())
    , middleware_(std::make_shared<Http::HttpMiddleware>())
{
    connHandler_ = CreateConnectionHandler(useHttps);
    if(!connHandler_)
        logger_.Fatal("[CoreEngine]: Failed to create connection backend");

    Shared::InitHttpAPIV1(connHandler_.get(), router_.get(), middleware_.get());
    Shared::InitAsyncAPIV1(connHandler_.get());
    SetMasterApi(Shared::GetMasterAPI());

    HandleUserDLLInjection(dllPath);
    HandleMiddlewareLoading();
}

// ---------------------------------------------------------------------------
// Worker constructor (engines 1..N)
// Receives engine 0's pre-populated Router and Middleware — no DLL loading,
// no route registration, no middleware loading.
// ---------------------------------------------------------------------------
CoreEngine::CoreEngine(std::shared_ptr<Http::Router>         sharedRouter,
                       std::shared_ptr<Http::HttpMiddleware>  sharedMiddleware,
                       bool                                   useHttps)
    : router_    (std::move(sharedRouter))
    , middleware_(std::move(sharedMiddleware))
{
    connHandler_ = CreateConnectionHandler(useHttps);
    if(!connHandler_)
        logger_.Fatal("[CoreEngine]: Failed to create connection backend");

    // Wire this engine's own connHandler into the HTTP API so in-flight
    // async callbacks resolve correctly on this thread.
    Shared::InitHttpAPIV1(connHandler_.get(), router_.get(), middleware_.get());
    Shared::InitAsyncAPIV1(connHandler_.get());
    SetMasterApi(Shared::GetMasterAPI());

    // Routes already registered into router_, middleware already loaded.
}

void CoreEngine::Listen(const std::string& host, std::uint16_t port)
{
    tl_currentEngine = this;  // pin for OnCoroutineComplete

    connHandler_->Initialize(host, port);
    connHandler_->SetEngineCallback(
        [this](ConnectionContext* ctx) { this->HandleRequest(ctx); }
    );
    connHandler_->Run();
}

void CoreEngine::Stop()
{
    connHandler_->Stop();
    logger_.Info("[CoreEngine]: Stopped Successfully!");
}

// vvv Internal Functions vvv

void CoreEngine::HandleRequest(ConnectionContext* ctx)
{
    WFX_TRACE();

    auto& networkConfig = config_.networkConfig;

    if(!ctx->responseInfo)
        ctx->responseInfo = new HttpResponse{};

    auto& res = *ctx->responseInfo;

    HttpParseState state = HttpParser::Parse(ctx);

    switch(state) {
        case HttpParseState::PARSE_INCOMPLETE_HEADERS:
        case HttpParseState::PARSE_INCOMPLETE_BODY:
            ctx->SetConnectionState(ConnectionState::CONNECTION_ALIVE);
            connHandler_->RefreshExpiry(ctx, state == HttpParseState::PARSE_INCOMPLETE_HEADERS
                                            ? networkConfig.headerTimeout
                                            : networkConfig.bodyTimeout);
            connHandler_->ResumeReceive(ctx);
            return;

        case HttpParseState::PARSE_EXPECT_100:
            ctx->SetConnectionState(ConnectionState::CONNECTION_ALIVE);
            connHandler_->RefreshExpiry(ctx, networkConfig.bodyTimeout);
            connHandler_->Write(ctx, "HTTP/1.1 100 Continue\r\n\r\n");
            return;

        case HttpParseState::PARSE_EXPECT_417:
            ctx->SetConnectionState(ConnectionState::CONNECTION_CLOSE);
            connHandler_->Write(ctx, "HTTP/1.1 417 Expectation Failed\r\n\r\n");
            return;

        case HttpParseState::PARSE_SUCCESS:
        {
            ctx->trackBytes = 0;

            auto& reqInfo    = *ctx->requestInfo;
            auto  connHeader = reqInfo.headers.GetHeader("Connection");
            auto  connMask   = HandleConnectionHeader(connHeader);

            if(connMask & ConnectionHeader::ERROR) {
                ctx->SetConnectionState(ConnectionState::CONNECTION_CLOSE);
                connHandler_->Write(ctx, HttpError::badRequest);
                return;
            }

            bool shouldClose = (connMask == ConnectionHeader::NONE)
                                ? (reqInfo.version == HttpVersion::HTTP_1_0)
                                : static_cast<bool>(connMask & ConnectionHeader::CLOSE);

            ctx->SetConnectionState(shouldClose
                ? ConnectionState::CONNECTION_CLOSE
                : ConnectionState::CONNECTION_ALIVE);

            if(!ctx->rwBuffer.IsWriteInitialized() &&
               !ctx->rwBuffer.InitWriteBuffer(networkConfig.maxSendBufferSize))
            {
                ctx->SetConnectionState(ConnectionState::CONNECTION_CLOSE);
                connHandler_->Write(ctx, HttpError::internalError);
                return;
            }

            res.Reset();
            res.SetRWBuffer(&ctx->rwBuffer);
            res.SetVersion(reqInfo.version);
            res.SetShouldClose(shouldClose);

            if(StartsWith(reqInfo.path, "/public/")) {
                std::string_view relativePath = reqInfo.path.substr(7);
                std::string fullRoute = config_.projectConfig.publicDir + std::string(relativePath);
                res.SendFile(fullRoute, true);
                goto __HandleResponse;
            }

            {
                auto node = router_->MatchRoute(reqInfo.method, reqInfo.path, reqInfo.pathSegments);
                if(!node) {
                    HandleError(ctx, HttpStatus::NOT_FOUND, "404: Route not found :(");
                    goto __HandleResponse;
                }

                reqInfo.routeNode_ = node;
                HandleSuccess(ctx);
                return;
            }

        __HandleResponse:
            FinishRequest(ctx);
            HandleResponse(ctx);
            return;
        }

        case HttpParseState::PARSE_ERROR:
            ctx->SetConnectionState(ConnectionState::CONNECTION_CLOSE);
            connHandler_->Write(ctx, HttpError::badRequest);
            return;

        case HttpParseState::PARSE_STREAMING_BODY:
        default:
            ctx->SetConnectionState(ConnectionState::CONNECTION_CLOSE);
            connHandler_->Write(ctx, HttpError::notImplemented);
            return;
    }
}

void CoreEngine::HandleResponse(ConnectionContext* ctx)
{
    WFX_TRACE();

    HttpResponse& res = *ctx->responseInfo;

    if(!res.IsCommitted())
        res.Commit();

    if(res.IsFile()) {
        connHandler_->WriteFile(ctx, res.TakeFilePath());
        return;
    }

    if(res.IsStream()) {
        connHandler_->Stream(ctx, res.TakeGenerator());
        return;
    }

    connHandler_->Write(ctx, {});
}

void CoreEngine::HandleSuccess(ConnectionContext* ctx)
{
    WFX_TRACE();

    auto* httpApi = Shared::GetHttpAPIV1();
    auto& req     = *ctx->requestInfo;
    auto& res     = *ctx->responseInfo;
    auto* node    = static_cast<const TrieNode*>(req.routeNode_);

    Response userRes{&res};
    Request  userReq{&req};

    ExecutionLevel eLevel = ctx->trackAsync.GetELevel();

    if(eLevel == ExecutionLevel::RESPONSE)
        goto __HandleResponse;

    if(eLevel == ExecutionLevel::MIDDLEWARE) {
        auto [success, isAsync, isBroken] = middleware_->ExecuteMiddleware(ctx, node, userReq, userRes);

        if(!success) {
            if(isBroken)
                goto __HandleResponse;

            if(!isAsync) {
                ctx->SetConnectionState(ConnectionState::CONNECTION_CLOSE);
                HandleError(ctx, HttpStatus::INTERNAL_SERVER_ERROR, "Middleware Execution Failure");
                goto __HandleResponse;
            }

            FinishRequest(ctx);
            return;
        }

        ctx->trackAsync.SetELevel(ExecutionLevel::RESPONSE);
    }

    if(node->callback.kind == CallbackKind::SYNC)
        node->callback.sync(userReq, userRes);
    else {
        httpApi->SetGlobalPtrData(static_cast<void*>(ctx));
        node->callback.async(userReq, userRes, CoreEngine::OnCoroutineComplete, ctx);
        httpApi->SetGlobalPtrData(nullptr);

        FinishRequest(ctx);
        return;
    }

__HandleResponse:
    FinishRequest(ctx);
    HandleResponse(ctx);
}

// vvv Helper Functions vvv

void CoreEngine::OnCoroutineComplete(void* ud, AsyncResult result)
{
    auto* ctx    = static_cast<ConnectionContext*>(ud);
    auto* engine = tl_currentEngine;  // thread-local — always the right engine

    if(result.status != AsyncStatus::COMPLETED) {
        ctx->SetConnectionState(ConnectionState::CONNECTION_CLOSE);
        engine->HandleError(ctx, HttpStatus::INTERNAL_SERVER_ERROR, "Async Failure");
    }
    else if(ctx->trackAsync.GetELevel() == ExecutionLevel::MIDDLEWARE) {
        *ctx->trackAsync.GetMAction() = result.action;
        engine->HandleSuccess(ctx);
        return;
    }

    engine->HandleResponse(ctx);
}

void CoreEngine::FinishRequest(ConnectionContext* ctx)
{
    ctx->SetParseState(HttpParseState::PARSE_IDLE);
    connHandler_->RefreshExpiry(ctx, config_.networkConfig.idleTimeout);
}

void CoreEngine::HandleError(ConnectionContext* ctx, Shared::HttpStatus code, std::string_view message)
{
    auto& res = *ctx->responseInfo;
    res.SetShouldClose(ctx->GetConnectionState() == ConnectionState::CONNECTION_CLOSE);
    res.AbortWithError(code, message);
}

std::uint8_t CoreEngine::HandleConnectionHeader(std::string_view header)
{
    std::uint8_t mask  = ConnectionHeader::NONE;
    std::size_t  start = 0;
    std::size_t  size  = header.size();

    while(start < size) {
        std::size_t end = header.find(',', start);
        if(end == std::string_view::npos)
            end = size;

        std::string_view token = TrimView(header.substr(start, end - start));

        if(StringCanonical::InsensitiveStringCompare(token, "close")) {
            if(mask & ConnectionHeader::KEEP_ALIVE)
                return ConnectionHeader::ERROR;
            mask |= ConnectionHeader::CLOSE;
        }
        else if(StringCanonical::InsensitiveStringCompare(token, "keep-alive")) {
            if(mask & ConnectionHeader::CLOSE)
                return ConnectionHeader::ERROR;
            mask |= ConnectionHeader::KEEP_ALIVE;
        }
        else if(StringCanonical::InsensitiveStringCompare(token, "upgrade"))
            mask |= ConnectionHeader::UPGRADE;
        else
            return ConnectionHeader::ERROR;

        start = end + 1;
    }

    return mask;
}

void CoreEngine::HandleUserDLLInjection(const char* dllPath)
{
#if defined(_WIN32)
    HMODULE userModule = LoadLibraryA(dllPath);
    if(!userModule) {
        DWORD err = GetLastError();
        logger_.Fatal("[CoreEngine]: ", dllPath, " was not found. Error: ", err);
        return;
    }

    FARPROC rawProc = GetProcAddress(userModule, "RegisterMasterAPI");
    if(!rawProc) {
        DWORD err = GetLastError();
        logger_.Fatal("[CoreEngine]: Failed to find RegisterMasterAPI() in user DLL. Error: ", err);
        return;
    }

    auto registerFn = reinterpret_cast<Shared::RegisterMasterAPIFn>(rawProc);
#else
    void* handle = dlopen(dllPath, RTLD_NOW | RTLD_GLOBAL);
    if(!handle) {
        const char* err = dlerror();
        logger_.Fatal("[CoreEngine]: ", dllPath, " dlopen failed: ", (err ? err : "unknown error"));
    }

    dlerror();
    void* rawSym = dlsym(handle, "RegisterMasterAPI");
    const char* dlsymErr = dlerror();
    if(!rawSym || dlsymErr)
        logger_.Fatal("[CoreEngine]: Failed to find RegisterMasterAPI() in user SO. Error: ",
                      (dlsymErr ? dlsymErr : "symbol not found"));

    auto registerFn = reinterpret_cast<Shared::RegisterMasterAPIFn>(rawSym);
#endif
    registerFn(Shared::GetMasterAPI());
    logger_.Info("[CoreEngine]: Successfully injected API and initialized user module: ", dllPath);
}

void CoreEngine::HandleMiddlewareLoading()
{
    middleware_->LoadMiddlewareFromConfig(config_.projectConfig.middlewareList);
    middleware_->DiscardFactoryMap();
}

} // namespace WFX::Core