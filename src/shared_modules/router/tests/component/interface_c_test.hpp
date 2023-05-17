/*
 * Wazuh router - Interface tests
 * Copyright (C) 2015, Wazuh Inc.
 * Apr 29, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _ROUTER_C_INTERFACE_TESTS_HPP
#define _ROUTER_C_INTERFACE_TESTS_HPP

#include "router.h"
#include <gtest/gtest.h>

class RouterCInterfaceTest : public ::testing::Test
{
protected:
    RouterCInterfaceTest() = default;
    ~RouterCInterfaceTest() override = default;

    void SetUp() override;
    void TearDown() override;

    ROUTER_PROVIDER_HANDLE m_routerProviderHandle {};
};
#endif //_ROUTER_C_INTERFACE_TESTS_HPP
