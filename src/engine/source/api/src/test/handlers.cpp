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

api::Handler testRunCmd()
{
    return [](api::wpRequest wRequest) -> api::wpResponse
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
        auto errorMsg = !eRequest.has_kvdbpath()         ? std::make_optional("Missing /kvdb path")
                        : !eRequest.has_filestorage() ? std::make_optional("Missing /file storage")
                        : !eRequest.has_policy()         ? std::make_optional("Missing /policy")
                                                         : std::nullopt;

        if (errorMsg.has_value())
        {
            return ::api::adapter::genericError<ResponseType>(errorMsg.value());
        }

        // Logging init
        logging::LoggingConfig logConfig;
        logConfig.logLevel = eRequest.loglevel();

        logging::loggingInit(logConfig);

        auto metricsManager = std::make_shared<metricsManager::MetricsManager>();

        auto kvdb = std::make_shared<kvdb_manager::KVDBManager>(eRequest.kvdbpath(), metricsManager);
        g_exitHanlder.add([kvdb]() { kvdb->clear(); });

        auto fileStore = std::make_shared<store::FileDriver>(eRequest.filestorage());

        base::Name hlpConfigFileName({"schema", "wazuh-logpar-types", "0"});
        auto hlpParsers = fileStore->get(hlpConfigFileName);
        if (std::holds_alternative<base::Error>(hlpParsers))
        {
            LOG_ERROR("Engine 'test' command: Configuration file '{}' could not be obtained: {}.",
                    hlpConfigFileName.fullName(),
                    std::get<base::Error>(hlpParsers).message);

            g_exitHanlder.execute();
            return ::api::adapter::genericError<ResponseType>("Engine 'test' command: Configuration file '{}' could not be obtained: {}.");
        }
        auto logpar = std::make_shared<hlp::logpar::Logpar>(std::get<json::Json>(hlpParsers));
        hlp::registerParsers(logpar);
        LOG_INFO("HLP initialized.");

        auto registry = std::make_shared<builder::internals::Registry<builder::internals::Builder>>();
        size_t logparDebugLvl = eRequest.debuglevel() > 2 ? 1 : 0;
        try
        {
            builder::internals::dependencies deps;
            deps.logparDebugLvl = logparDebugLvl;
            deps.logpar = logpar;
            deps.kvdbManager = kvdb;
            deps.helperRegistry = std::make_shared<builder::internals::Registry<builder::internals::HelperBuilder>>();
            builder::internals::registerHelperBuilders(deps.helperRegistry, deps);
            builder::internals::registerBuilders(registry, deps);
        }
        catch (const std::exception& e)
        {
            LOG_ERROR("Engine 'test' command: An error occurred while registering the builders: {}.",
                    utils::getExceptionStack(e));
            g_exitHanlder.execute();
            return ::api::adapter::genericError<ResponseType>(e.what());
        }

        // Delete outputs
        try
        {
            base::Name envName {eRequest.policy()};
        }
        catch (const std::exception& e)
        {
            LOG_ERROR("Engine 'test' command: An error occurred while creating the policy '{}': {}.",
                    eRequest.policy(),
                    utils::getExceptionStack(e));
            g_exitHanlder.execute();
            return ::api::adapter::genericError<ResponseType>(e.what());
        }
        auto envDefinition = fileStore->get({eRequest.policy()});
        if (std::holds_alternative<base::Error>(envDefinition))
        {
            LOG_ERROR("Engine 'test' command: An error occurred while getting the definition of the policy '{}': {}.",
                    eRequest.policy(),
                    std::get<base::Error>(envDefinition).message);
            g_exitHanlder.execute();
            return ::api::adapter::genericError<ResponseType>("Engine 'test' command: An error occurred while getting the definition of the policy");
        }
        json::Json envTmp {std::get<json::Json>(envDefinition)};
        envTmp.erase("/outputs");

        // Fake catalog for testing
        struct TestDriver : store::IStoreRead
        {
            std::shared_ptr<store::FileDriver> driver;
            json::Json testPolicy;

            std::variant<json::Json, base::Error> get(const base::Name& name) const
            {
                if ("policy" == name.parts()[0])
                {
                    return testPolicy;
                }
                else
                {
                    return driver->get(name);
                }
            }
        };
        auto _testDriver = std::make_shared<TestDriver>();
        _testDriver->driver = fileStore;
        _testDriver->testPolicy = envTmp;

        // TODO: Handle errors on construction
        builder::Builder _builder(_testDriver, registry);
        decltype(_builder.buildPolicy({eRequest.policy()})) env;
        try
        {
            env = _builder.buildPolicy({eRequest.policy()});
        }
        catch (const std::exception& e)
        {
            LOG_ERROR("Engine 'test' command: An error occurred while building the policy '{}': {}.",
                    eRequest.policy(),
                    utils::getExceptionStack(e));
            g_exitHanlder.execute();
            return ::api::adapter::genericError<ResponseType>(e.what());
        }

        // Create rxbackend
        auto controller = rxbk::buildRxPipeline(env);
        g_exitHanlder.add([&controller]() { controller.complete(); });

        // output
        std::stringstream output;
        auto stderrSubscriber = rxcpp::make_subscriber<rxbk::RxEvent>(
            [&](const rxbk::RxEvent& event) { output << event->payload()->prettyStr() << std::endl; });
        controller.getOutput().subscribe(stderrSubscriber);

        // Tracer subscriber for history
        // TODO: update once proper tracing is implemented
        std::vector<std::pair<std::string, std::string>> history {};
        if (eRequest.debuglevel() > 0)
        {
            auto conditionRegex = std::make_shared<RE2>(R"(\[([^\]]+)\] \[condition\]:(.+))");
            controller.listenOnAllTrace(rxcpp::make_subscriber<std::string>(
                [&history, conditionRegex](const std::string& trace)
                {
                    std::string asset;
                    std::string result;
                    auto matched = RE2::FullMatch(trace, *conditionRegex, &asset, &result);
                    if (matched)
                    {
                        history.push_back({asset, result});
                    }
                }));
        }

        // Tracer subscriber for full debug
        std::unordered_map<std::string, std::stringstream> traceBuffer;
        if (eRequest.debuglevel() > 1)
        {
            if (eRequest.assettrace().empty())
            {
                auto assetNamePattern = std::make_shared<RE2>(R"(^\[([^\]]+)\].+)");
                controller.listenOnAllTrace(rxcpp::make_subscriber<std::string>(
                    [assetNamePattern, &traceBuffer](const std::string& trace)
                    {
                        std::string asset;
                        auto matched = RE2::PartialMatch(trace, *assetNamePattern, &asset);
                        traceBuffer[asset] << trace << std::endl;
                    }));
            }
            else
            {
                for (auto& name : eRequest.assettrace())
                {
                    try
                    {
                        controller.listenOnTrace(
                            name,
                            rxcpp::make_subscriber<std::string>([&, name](const std::string& trace)
                                                                { traceBuffer[name] << trace << std::endl; }));
                    }
                    catch (const std::exception& e)
                    {
                        LOG_WARNING("Engine 'test' command: Asset '{}' could not found, skipping tracer: {}.",
                                    name,
                                    utils::getExceptionStack(e));
                        return ::api::adapter::genericError<ResponseType>(e.what());
                    }
                }
            }
        }

        // Give time to logger
        // TODO: fix logger
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        // Stdin loop
        while (gs_doRun)
        {
            std::cout << std::endl << std::endl << "Enter a log in single line (Crtl+C to exit):" << std::endl << std::endl;
            std::string line;
            std::getline(std::cin, line);
            if (line.empty())
            {
                continue;
            }
            try
            {
                // Clear outputs
                history.clear();
                output.str("");
                output.clear();

                // Send event
                auto event = fmt::format("{}:{}:{}", eRequest.protocolqueue(), eRequest.protocollocation(), line);
                auto result = base::result::makeSuccess(base::parseEvent::parseOssecEvent(event));
                controller.ingestEvent(std::make_shared<base::result::Result<base::Event>>(std::move(result)));

                // Decoder history
                if (eRequest.debuglevel() > 0)
                {
                    std::cerr << std::endl << std::endl << "DECODERS:" << std::endl;
                    std::string indent = "  ";
                    for (auto& [asset, condition] : history)
                    {
                        if (builder::Asset::Type::DECODER == env.assets()[asset]->m_type)
                        {
                            std::cerr << fmt::format("{}{}  ->  {}", indent, asset, condition) << std::endl;
                            if (traceBuffer.find(asset) != traceBuffer.end())
                            {
                                std::string line;
                                while (std::getline(traceBuffer[asset], line))
                                {
                                    std::cerr << indent << indent << line << std::endl;
                                }
                            }
                            // Clear trace buffer
                            traceBuffer[asset].str("");
                            traceBuffer[asset].clear();
                            if ("success" == condition)
                            {
                                indent += indent;
                            }
                        }
                    }
                    // Rule history
                    std::cerr << std::endl << "RULES:" << std::endl;
                    indent = "  ";
                    for (auto& [asset, condition] : history)
                    {
                        if (builder::Asset::Type::RULE == env.assets()[asset]->m_type)
                        {
                            std::cerr << fmt::format("{}{}  ->  {}", indent, asset, condition) << std::endl;
                            if (traceBuffer.find(asset) != traceBuffer.end())
                            {
                                std::string line;
                                while (std::getline(traceBuffer[asset], line))
                                {
                                    std::cerr << indent << indent << line << std::endl;
                                }
                            }

                            // Clear trace buffer
                            traceBuffer[asset].str("");
                            traceBuffer[asset].clear();
                            if ("success" == condition)
                            {
                                indent += indent;
                            }
                        }
                    }
                }

                // Output
                std::cerr << std::endl << std::endl << "OUTPUT:" << std::endl << std::endl;
                std::cerr << output.str() << std::endl;
            }
            catch (const std::exception& e)
            {
                LOG_ERROR("Engine 'test' command: An error occurred while parsing a message: {}.", e.what());
                return ::api::adapter::genericError<ResponseType>(e.what());
            }
        }

        g_exitHanlder.execute();

        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);

        return ::api::adapter::toWazuhResponse(eResponse);
    };
}

void registerHandlers(std::shared_ptr<api::Api> api)
{
    try
    {
        api->registerHandler("test.resource/run", testRunCmd());
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error(fmt::format("metrics API commands could not be registered: {}", e.what()));
    }
}
} // namespace api::test::handlers
