#ifndef WFX_HTTP_CONNECTION_FACTORY_HPP
#define WFX_HTTP_CONNECTION_FACTORY_HPP

#include "http_connection.hpp"
#include <memory>

#ifdef _WIN32
    #include "os_specific/windows/iocp_connection.hpp"
#elif defined(__APPLE__)
    #include "os_specific/macos/kqueue_connection.hpp"
#else
    #ifdef WFX_LINUX_USE_IO_URING
        #include "os_specific/linux/io_uring_connection.hpp"
    #else
        #include "os_specific/linux/epoll_connection.hpp"
    #endif
#endif

namespace WFX::Http {

inline std::unique_ptr<HttpConnectionHandler> CreateConnectionHandler(bool useHttps)
{
#ifdef _WIN32
    return std::make_unique<OSSpecific::IocpConnectionHandler>(useHttps);
#elif defined(__APPLE__)
    return std::make_unique<OSSpecific::KqueueConnectionHandler>(useHttps);
#else
    #ifdef WFX_LINUX_USE_IO_URING
        return std::make_unique<OSSpecific::IoUringConnectionHandler>(useHttps);
    #else
        return std::make_unique<OSSpecific::EpollConnectionHandler>(useHttps);
    #endif
#endif
}

} // namespace WFX::Http
#endif // WFX_HTTP_CONNECTION_FACTORY_HPP