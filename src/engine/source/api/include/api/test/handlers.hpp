#ifndef _API_TEST_HANDLERS_HPP
#define _API_TEST_HANDLERS_HPP

#include <api/api.hpp>
#include <router/router.hpp>

/**
 * @brief Test configuration parameters.
 *
 */
struct Config
{
    std::shared_ptr<router::Router> router;
};

namespace api::test::handlers
{
    /**
     * @brief 
     * 
     */
    api::Handler testRunCmd(const Config& config);

    /**
     * @brief Register all handlers for the test API.
     * 
     * @param config Test configuration.
     * @param api API instance.
     * @throw std::runtime_error If the command registration fails for any reason and at any
     */
    void registerHandlers(const Config& config, std::shared_ptr<api::Api> api);

} // namespace api::test::handlers

#endif // _API_TEST_HANDLERS_HPP
