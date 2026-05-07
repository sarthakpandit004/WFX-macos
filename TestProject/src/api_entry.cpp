#include <shared/apis/master_api.hpp>
#include <shared/utils/deferred_init_vector.hpp>
#include <shared/utils/compiler_macro.hpp>

// WARNING: DO NOT MODIFY THIS SYMBOL OR THIS FILE
// __WFXApi is reserved for WFX internal API injection
// Modifying or redefining it will break the interface between WFX and USER
const WFX::Shared::MASTER_API_TABLE* __WFXApi = nullptr;

// To prevent name mangling 
extern "C" {
    WFX_EXPORT void RegisterMasterAPI(const WFX::Shared::MASTER_API_TABLE* api)
    {
        static bool registered = false;
        if(registered)
            return;

        if(api) {
            __WFXApi = api;

            auto& constructors = WFX::Shared::__WFXDeferredConstructors;
            auto& middlewares  = WFX::Shared::__WFXDeferredMiddleware;
            auto& routes       = WFX::Shared::__WFXDeferredRoutes;

            for(auto& fn : constructors)
                fn();

            for(auto& fn : middlewares)
                fn();

            for(auto& fn : routes)
                fn();

            // Clean up memory
            WFX::Shared::__EraseDeferredVector(constructors);
            WFX::Shared::__EraseDeferredVector(middlewares);
            WFX::Shared::__EraseDeferredVector(routes);

            registered = true;
        }
    }
}