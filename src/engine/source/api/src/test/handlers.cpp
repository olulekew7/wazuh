#include "api/test/handlers.hpp"

#include <json/json.hpp>

#include <api/adapter.hpp>

#include <atomic>
#include <chrono>
#include <cmds/details/stackExecutor.hpp>
#include <memory>
#include <thread>

#include <re2/re2.h>
#include <hlp/logpar.hpp>
#include <hlp/registerParsers.hpp>
#include <kvdb/kvdbManager.hpp>
#include <logging/logging.hpp>
#include <metrics/metricsManager.hpp>
#include <name.hpp>
#include <rxbk/rxFactory.hpp>
#include <store/drivers/fileDriver.hpp>

#include "base/parseEvent.hpp"
#include "base/utils/getExceptionStack.hpp"
#include "builder.hpp"

#include <eMessages/eMessage.h>
#include <eMessages/tests.pb.h>

#include <api/adapter.hpp>

#include "register.hpp"
#include "registry.hpp"

namespace api::test::handlers
{

namespace eTest = ::com::wazuh::api::engine::test;
namespace eEngine = ::com::wazuh::api::engine;

/* Manager Endpoint */
std::atomic<bool> gs_doRun = true;
cmd::details::StackExecutor g_exitHanlder {};
void sigint_handler(const int signum)
{
    gs_doRun = false;
}

api::Handler testRunCmd(const Config& config)
{
    return [config](api::wpRequest wRequest) -> api::wpResponse
    {
        using RequestType = eTest::Run_Request;
        using ResponseType = eTest::Run_Response;
        auto res = ::api::adapter::fromWazuhRequest<RequestType, ResponseType>(wRequest);

        // If the request is not valid, return the error
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }

        // Validate the params request
        const auto& eRequest = std::get<RequestType>(res);
        auto errorMsg = !eRequest.has_policy()      ? std::make_optional("Missing /policy name")
                        : !eRequest.has_event()     ? std::make_optional("Missing /event")
                        : !eRequest.has_debugmode() ? std::make_optional("Missing /debug mode")
                        : !eRequest.has_protocolqueue() ? std::make_optional("Missing /protocol queue")
                        : std::nullopt;

        if (errorMsg.has_value())
        {
            return ::api::adapter::genericError<ResponseType>(errorMsg.value());
        }

        auto event = fmt::format("{}:{}:{}", eRequest.protocolqueue(), "/dev/stdin", eRequest.event().string_value());
        config.router->enqueueOssecEvent(event);

        ResponseType eResponse;

        const auto protoVal = eMessage::eMessageFromJson<google::protobuf::Value>(config.router->getOutput());
        const auto jsonValue = std::get<google::protobuf::Value>(protoVal);
        eResponse.mutable_output()->CopyFrom(jsonValue);

        eResponse.set_status(eEngine::ReturnStatus::OK);

        return ::api::adapter::toWazuhResponse(eResponse);
    };
}

void registerHandlers(const Config& config, std::shared_ptr<api::Api> api)
{
    try
    {
        api->registerHandler("test.resource/run", testRunCmd(config));
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error(fmt::format("test API commands could not be registered: {}", e.what()));
    }
}
} // namespace api::test::handlers
