'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: The wazuh-analysisd daemon uses a series of decoders and rules to analyze and interpret logs and events and
       generate alerts when the decoded information matches the established rules. The 'if_sid' option is used to
       associate a rule to a parent rule by referencing the rule ID of the parent. This test module checks that when
       an valid rule_id is used, the rule is not ignored.

components:
    - analysisd

suite: analysisd

targets:
    - manager

daemons:
    - wazuh-analysisd

os_platform:
    - linux

os_version:
    - Arch Linux
    - Amazon Linux 2
    - Amazon Linux 1
    - CentOS 8
    - CentOS 7
    - Debian Buster
    - Red Hat 8
    - Ubuntu Focal
    - Ubuntu Bionic

references:
    - https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html#if-sid
'''
import pytest

from pathlib import Path

from wazuh_testing.constants.paths.logs import OSSEC_LOG_PATH
from wazuh_testing.modules.analysisd.testrule import patterns
from wazuh_testing.utils.config import load_configuration_template, get_test_cases_data
from wazuh_testing.tools.file_monitor import FileMonitor, generate_callback

from . import CONFIGS_PATH, TEST_CASES_PATH, RULES_SAMPLE_PATH


pytestmark = [pytest.mark.server, pytest.mark.tier(level=1)]

# Configuration and cases data.
configs_path = Path(CONFIGS_PATH, 'config_signature_id_values.yaml')
cases_path = Path(TEST_CASES_PATH, 'cases_valid_signature_id.yaml')

# Test configurations.
config_parameters, metadata, cases_ids = get_test_cases_data(cases_path)
configuration = load_configuration_template(configs_path, config_parameters, metadata)


# Test function.
@pytest.mark.parametrize('configuration, metadata', zip(configuration, metadata), ids=cases_ids)
def test_valid_signature_id(configuration, metadata, set_wazuh_configuration, truncate_monitored_files,
                            prepare_custom_rules_file, restart_wazuh_function):
    '''
    description: Check that when a rule has an valid signature ID value assigned to the if_sid option, the rule is
                 not ignored.

    test_phases:
        - Setup:
            - Set wazuh configuration.
            - Copy custom rules file into manager
            - Clean logs files and restart wazuh to apply the configuration.
        - Test:
            - Check no log for "if_sid not found" is detected
            - Check no log for "empty if_sid" is detected
            - Check no log for "invalid if_sid" is detected
        - Tierdown:
            - Delete custom rule file
            - Restore configuration
            - Stop wazuh

    wazuh_min_version: 4.4.0

    tier: 1

    parameters:
        - configuration:
            type: dict
            brief: Configuration loaded from `config_templates`.
        - metadata:
            type: dict
            brief: Test case metadata.
        - set_wazuh_configuration:
            type: fixture
            brief: Set wazuh configuration.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate all the log files and json alerts files before and after the test execution.
        - prepare_custom_rules_file:
            type: fixture
            brief: Copies custom rules_file before test, deletes after test.
        - restart_wazuh_function:
            type: fixture
            brief: Restart wazuh at the start of the module to apply configuration.

    assertions:
        - Check that wazuh starts
        - Check ".*Signature ID '(\\d*)' was not found and will be ignored in the 'if_sid'.* of rule '(\\d*)'" event
        - Check ".*wazuh-testrule.*Empty 'if_sid' value. Rule '(\\d*)' will be ignored.*"

    input_description:
        - The `config_signature_id_values.yaml` file provides the module configuration for
          this test.
        - The `cases_valid_signature_id.yaml` file provides the test cases.
    '''
    # Start monitors
    monitor_not_found = FileMonitor(OSSEC_LOG_PATH, generate_callback(patterns.SID_NOT_FOUND))
    monitor_empty = FileMonitor(OSSEC_LOG_PATH, generate_callback(patterns.EMPTY_IF_SID_RULE_IGNORED))
    monitor_invalid = FileMonitor(OSSEC_LOG_PATH, generate_callback(patterns.INVALID_IF_SID_RULE_IGNORED))

    # Check that no log appears for rules if_sid field pointing to a non existent SID
    assert not monitor_not_found.callback_result
    # Check that no log appears for rules if_sid field being empty string
    assert not monitor_empty.callback_result
    # Check that no log appears for rules if_sid field being invalid
    assert not monitor_invalid.callback_result
