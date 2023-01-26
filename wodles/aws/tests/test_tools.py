import argparse
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

import aws_tools

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '.'))
import aws_utils as utils


@pytest.mark.parametrize('msg_level', range(3))
@patch('builtins.print')
def test_debug(mock_print, msg_level):
    """Test 'debug' function only prints messages with a level equal or greater than the debug level."""
    msg = "test message"
    aws_tools.debug(msg, msg_level)
    if aws_tools.debug_level >= msg_level:
        mock_print.assert_called_with(f"DEBUG: {msg}")
    else:
        mock_print.assert_not_called()


def test_arg_valid_date():
    """Test 'arg_valid_date' function returns a string with the expected format."""
    parsed_date = aws_tools.arg_valid_date("2022-JAN-01")
    assert isinstance(parsed_date, str)
    assert parsed_date == "20220101"


def test_arg_valid_date_ko():
    """Test 'arg_valid_date' function raises an 'ArgumentTypeError' error if the format provided is not supported."""
    with pytest.raises(argparse.ArgumentTypeError):
        aws_tools.arg_valid_date("2022-01-01")


@pytest.mark.parametrize('arg_string', ['prefix', 'prefix/', None])
def test_arg_valid_prefix(arg_string: str or None):
    """Test 'arg_valid_prefix' function returns the expected prefix.

    Parameters
    ----------
    arg_string: str or None
        String containing the prefix to be formatted.
    """
    prefix = aws_tools.arg_valid_prefix(arg_string)
    if arg_string:
        assert isinstance(prefix, str)
        assert prefix[-1] == "/"
        assert arg_string in prefix


@pytest.mark.parametrize('arg_string', [
    utils.TEST_ACCOUNT_ID,
    f'{utils.TEST_ACCOUNT_ID},{utils.TEST_ACCOUNT_ID}',
    f'{utils.TEST_ACCOUNT_ID},{utils.TEST_ACCOUNT_ID},{utils.TEST_ACCOUNT_ID}',
    None
])
def test_arg_valid_accountid(arg_string: str or None):
    """Test 'arg_valid_accountid' function returns the expected number of account IDs.

    Parameters
    ----------
    arg_string: str or None
        String of account ids separated by comma.
    """
    account_ids = aws_tools.arg_valid_accountid(arg_string)
    assert isinstance(account_ids, list)
    assert len(account_ids) == (len(arg_string.split(',')) if arg_string else 0)


@pytest.mark.parametrize('arg_string', [
    utils.TEST_ACCOUNT_ID[:-1],
    f'{utils.TEST_ACCOUNT_ID},{utils.TEST_ACCOUNT_ID[:-1]}',
    f'{utils.TEST_ACCOUNT_ID},{utils.TEST_ACCOUNT_ID},123456789abc'
])
def test_arg_valid_accountid_ko(arg_string):
    """Test 'arg_valid_accountid' function raises an 'ArgumentTypeError' error
    if the number of digits is different to 12 or the account id is not formed only by digits.

    Parameters
    ----------
    arg_string: str or None
        String of account ids separated by comma.
    """
    with pytest.raises(argparse.ArgumentTypeError):
        aws_tools.arg_valid_accountid(arg_string)


@pytest.mark.parametrize('arg_string', [
    utils.TEST_REGION,
    f'{utils.TEST_REGION},{utils.TEST_REGION}',
    f'{utils.TEST_REGION},{utils.TEST_REGION},{utils.TEST_REGION}',
    None
])
def test_arg_valid_regions(arg_string):
    """Test 'arg_valid_regions' function returns the expected number of regions.

    Parameters
    ----------
    arg_string: str or None
        String of regions separated by comma.
    """
    regions = aws_tools.arg_valid_regions(arg_string)
    assert isinstance(regions, list)
    assert len(regions) == (len(arg_string.split(',')) if arg_string else 0)


@pytest.mark.parametrize('arg_string', ["900", "3600"])
def test_arg_valid_iam_role_duration(arg_string: str):
    """Test 'arg_valid_iam_role_duration' function returns the expected duration.

    Parameters
    ----------
    arg_string: str
        The desired session duration in seconds.
    """
    duration = aws_tools.arg_valid_iam_role_duration(arg_string)
    assert isinstance(duration, int)
    assert duration == int(arg_string)


@pytest.mark.parametrize('arg_string', ["899", "3601"])
def test_arg_valid_iam_role_duration_ko(arg_string):
    """Test 'arg_valid_iam_role_duration' function raises an 'ArgumentTypeError' error
    when the duration is not between 15m and 12h.

    Parameters
    ----------
    arg_string: str
        The desired session duration in seconds.
    """
    with pytest.raises(argparse.ArgumentTypeError):
        aws_tools.arg_valid_iam_role_duration(arg_string)


@patch('configparser.RawConfigParser')
def test_get_aws_config_params(mock_config):
    """Test 'get_aws_config_params' function returns the expected configparser.RawConfigParser object"""
    config = MagicMock()
    mock_config.return_value = config
    assert aws_tools.get_aws_config_params() == config
    config.read.assert_called_with(aws_tools.DEFAULT_AWS_CONFIG_PATH)


@pytest.mark.parametrize('mutually_exclusive_parameter', ['--bucket', '--service'])
def test_get_script_arguments(capsys, mutually_exclusive_parameter):
    """Test 'get_script_arguments' function shows no messages when the required parameters were provided."""
    with patch("sys.argv", ['main', mutually_exclusive_parameter, 'any']):
        aws_tools.get_script_arguments()
    stdout, stderr = capsys.readouterr()
    assert stdout == "", 'stdout was not empty'
    assert stderr == "", 'stderr was not empty'


@pytest.mark.parametrize('args', [
    ['main'],
])
def test_get_script_arguments_required(capsys, args):
    """Test 'get_script_arguments' function shows an error message when the required parameters are not provided."""
    with patch("sys.argv", args), pytest.raises(SystemExit) as exception:
        aws_tools.get_script_arguments()
    stdout, stderr = capsys.readouterr()
    assert stdout == "", 'The output was not empty'
    assert stderr != "", 'No error message was found in the output'
    assert exception.value.code == 2
