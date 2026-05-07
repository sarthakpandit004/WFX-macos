#include <http/routes.hpp>

WFX_GET("/", [](Request& req, Response res) {
    res.Status(HttpStatus::OK)
       .SendText("Hello from WFX on macOS!");
});

WFX_GET("/text", [](Request& req, Response res) {
    res.SendText("Hello from WFX :)");
});

WFX_GET("/json", [](Request& req, Response res) {
    res.SendJson(Json::object({
        {"WFX says", "Hello :)"}
    }));
});
