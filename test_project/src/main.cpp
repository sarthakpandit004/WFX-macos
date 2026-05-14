#include <wfx/http.hpp>


WFX_GET("/text", [](WFX::Request req, WFX::Response res) {
    res.SendText("Hello from WFX :)");
})

WFX_GET("/im-json", [](WFX::Request req, WFX::Response res) {
    auto j = WFX::ImJson(res);
    j.Write("WFX", "Says hello!");
})

WFX_GET("/rm-json", [](WFX::Request req, WFX::Response res) {
    auto o = WFX::RmJson();
    o["WFX"] = "Ain't this FRAMEWORK soooo, WEIRD? EXACTLY!";

    o.Write(res);
})

WFX_GET("/template", [](WFX::Request req, WFX::Response res) {
    res.SendTemplate("index.html", WFX::JsonObject{});
})
