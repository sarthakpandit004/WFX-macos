#include "run.hpp"

#include "cli/commands/common/common.hpp"
#include "config/config.hpp"
#include "engine/core_engine.hpp"
#include "engine/template_engine.hpp"
#include "http/common/http_global_state.hpp"
#include "utils/dotenv/dotenv.hpp"
#include "utils/logger/logger.hpp"
#include "utils/fileops/filesystem.hpp"
#include "utils/backport/string.hpp"
#include "utils/crash_tracer/crash_tracer.hpp"

#ifdef _WIN32
    #include <windows.h>
#else
    #include <sys/wait.h>
    #include <unistd.h>
    #include <signal.h>
#endif
#include <memory>
#include <thread>
#include <vector>

namespace WFX::CLI {

using namespace WFX::Http;
using namespace WFX::Utils;
using namespace WFX::Core;

int RunServer(const std::string& project, const ServerConfig& cfg)
{
    auto& logger      = Logger::GetInstance();
    auto& config      = Config::GetInstance();
    auto& globalState = GetGlobalState();
    auto& osConfig    = config.osSpecificConfig;
    auto& buildConfig = config.buildConfig;

    if(!FileSystem::DirectoryExists(project.c_str()))
        logger.Fatal("[WFX]: '", project, "' directory does not exist");

    const std::string crashLogDir = project + "/" + config.miscConfig.crashLogDir;
    if(!FileSystem::DirectoryExists(crashLogDir.c_str()) && !FileSystem::CreateDirectory(crashLogDir))
        logger.Fatal("[WFX]: Failed to create '", crashLogDir, "' directory for crash dumps");

#ifdef _WIN32
    logger.Fatal("[WFX]: Re-implement 'Run' for 'Windows' properly!");
#else
    // -------------------- LOADING PHASE --------------------
    config.LoadCoreSettings(project + "/wfx.toml");
    config.LoadFinalSettings(project);

    EnvConfig envConfig;
    envConfig.SetFlag(EnvFlags::REQUIRE_OWNER_UID);
    envConfig.SetFlag(EnvFlags::REQUIRE_PERMS_600);

    if(Dotenv::LoadFromFile(config.envConfig.envPath, envConfig))
        logger.Info("[WFX-Master]: Loaded '.env' successfully");

    // -------------------- INITIALIZING PHASE --------------------
    signal(SIGINT,  HandleMasterSignal);
    signal(SIGTERM, HandleMasterSignal);
    signal(SIGPIPE, SIG_IGN);
    signal(SIGHUP,  SIG_IGN);

    if(!RandomPool::GetInstance().GetBytes(globalState.sslKey.data(), globalState.sslKey.size()))
        logger.Fatal("[WFX-Master]: Failed to initialize SSL key");

    // -------------------- TEMPLATE / USER CODE COMPILATION PHASE --------------------
    HandleBuildDirectory();

    auto& templateEngine = TemplateEngine::GetInstance();
    auto [success, hasDynamic] = templateEngine.PreCompileTemplates();

    if(!success || !hasDynamic)
        HandleUserCxxCompilation(CxxCompilationOption::SOURCE_ONLY);
    else
        HandleUserCxxCompilation();

    templateEngine.LoadDynamicTemplatesFromLib();

    bool pinToCpu = cfg.GetFlag(ServerFlags::PIN_TO_CPU);
    bool useHttps = cfg.GetFlag(ServerFlags::USE_HTTPS);
    bool ohp      = cfg.GetFlag(ServerFlags::OVERRIDE_HTTPS_PORT);

    std::uint16_t port = useHttps && !ohp ? 443U : cfg.port;

    logger.Info("[WFX-Master]: Dev server running at ", useHttps ? "https://" : "http://", cfg.host, ':', port);
    logger.Info("[WFX-Master]: Press Ctrl+C to stop");
    logger.SetLevelMask(WFX_LOG_INFO | WFX_LOG_WARNINGS);

    // -------------------- WORKERS SPAWNING PHASE --------------------
#ifdef __APPLE__
    const std::string dllDir = buildConfig.buildDir + "/user_entry.dylib";
#else
    const std::string dllDir = buildConfig.buildDir + "/user_entry.so";
#endif

#if 0 && defined(__APPLE__)
    // ----------------------------------------------------------------
    // macOS: SO_REUSEPORT does NOT load-balance across processes —
    // the kernel pins all connections to one process.
    // Fix: all workers run as threads in ONE process, each with their own
    // kqueue fd.  The kernel distributes new connections across them.
    //
    // Route registration fix:
    //   dlopen() with RTLD_GLOBAL is reference-counted — it returns the same
    //   handle every time for the same path.  RegisterMasterAPI in the user
    //   DLL has a "static bool registered" guard that makes every call after
    //   the first a no-op.  If each engine tried to register routes into its
    //   own router, engines 1..N would always get empty routers → 100% 404.
    //
    //   Fix: engine 0 uses the full constructor (loads DLL, registers routes,
    //   loads middleware once).  Engines 1..N use the worker constructor which
    //   receives engine 0's shared_ptr<Router> and shared_ptr<Middleware> —
    //   routes are registered exactly once and all engines read the same
    //   immutable trie concurrently (safe: read-only after construction).
    // ----------------------------------------------------------------
    {
        BufferPool::GetInstance().Init(1024 * 1024, [](std::size_t curSize) { return curSize * 2; });
        FileCache::GetInstance().Init(config.miscConfig.fileCacheSize);
        CrashTracer::Install(crashLogDir.c_str());

        std::uint32_t numWorkers = osConfig.workerProcesses;
        logger.Info("[WFX-Master]: Spawning ", numWorkers, " worker threads (macOS thread mode)");

        std::vector<std::unique_ptr<CoreEngine>> engines;
        engines.reserve(numWorkers);

        // --- Engine 0: full init (loads DLL, registers routes) ---
        engines.push_back(std::make_unique<CoreEngine>(dllDir.c_str(), useHttps));
        globalState.enginePtr = engines[0].get();

        // --- Engines 1..N: share engine 0's router + middleware ---
        auto sharedRouter     = engines[0]->GetRouter();
        auto sharedMiddleware = engines[0]->GetMiddleware();

        for(std::uint32_t i = 1; i < numWorkers; i++)
            engines.push_back(
                std::make_unique<CoreEngine>(sharedRouter, sharedMiddleware, useHttps));

        // --- Spawn worker threads (only Listen(), no construction) ---
        std::vector<std::thread> workers;
        workers.reserve(numWorkers);

        for(std::uint32_t i = 0; i < numWorkers; i++) {
            workers.emplace_back([&engines, &cfg, port, pinToCpu, i]() {
                if(pinToCpu)
                    PinWorkerToCPU(i);
                engines[i]->Listen(cfg.host, port);
            });
        }

        // Wait for stop signal
        while(!globalState.shouldStop)
            pause();

        logger.Info("[WFX-Master]: Signal received, stopping worker threads...");

        for(auto& e : engines)
            e->Stop();

        for(auto& t : workers) {
            if(t.joinable())
                t.join();
        }
    }

#else
    // ----------------------------------------------------------------
    // Linux: fork() + SO_REUSEPORT works correctly, keep existing logic
    // ----------------------------------------------------------------
    for(int i = 0; i < (int)osConfig.workerProcesses; i++) {
        pid_t pid = fork();

        if(pid == 0) {
            if(i == 0)
                setpgid(0, 0);
            else
                setpgid(0, globalState.workerPGID);

            char workerName[32];
            std::snprintf(workerName, sizeof(workerName), "worker-%d", i);
            CrashTracer::SetWorkerName(workerName);
            CrashTracer::Install(crashLogDir.c_str());

            BufferPool::GetInstance().Init(1024 * 1024, [](std::size_t curSize) { return curSize * 2; });
            FileCache::GetInstance().Init(config.miscConfig.fileCacheSize);

            CoreEngine engine{dllDir.c_str(), useHttps};
            globalState.enginePtr = &engine;

            signal(SIGTERM, HandleWorkerSignal);
            signal(SIGINT,  SIG_IGN);
            signal(SIGPIPE, SIG_IGN);
            signal(SIGHUP,  SIG_IGN);

            if(pinToCpu)
                PinWorkerToCPU(i);

            engine.Listen(cfg.host, port);
            return 0;
        }
        else if(pid > 0) {
            globalState.workerPids.push_back(pid);
            if(i == 0)
                globalState.workerPGID = pid;
            setpgid(pid, globalState.workerPGID);
        }
        else {
            logger.Error("[WFX-Master]: Failed to fork worker ", i);
            return 1;
        }
    }

    while(!globalState.shouldStop)
        pause();

    logger.Info("[WFX-Master]: Signal received (INT / TERM), waiting for workers to shutdown...");

    for(std::uint32_t i = 0; i < osConfig.workerProcesses; i++) {
        pid_t pid    = globalState.workerPids[i];
        bool  exited = false;

        for(std::uint32_t t = 0; t < config.osSpecificConfig.workerShutdownTimeout * 10; t++) {
            int   status;
            pid_t ret = waitpid(pid, &status, WNOHANG);

            if(ret == pid) { exited = true; break; }

            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        if(!exited) {
            kill(pid, SIGKILL);
            waitpid(pid, nullptr, 0);
        }
    }
#endif // __APPLE__

#endif // _WIN32

    logger.Info("[WFX-Master]: Shutdown successfully");
    return 0;
}

}  // namespace WFX::CLI
