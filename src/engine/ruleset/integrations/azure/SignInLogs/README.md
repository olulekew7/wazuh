# Azure Integration - SignInLogs


|   |   |
|---|---|
| event.module | azure-SignInLogs |

This integration processes events logs from Azure

## Compatibility

SignInLogs decoder for Azure integration

## Configuration

This integration works using Wazuh Log Analytics with Azure. Use this wodle to collect Azure Log Analitycs logs
```html <wodle name="azure-logs">
  <disabled>no</disabled>
  <run_on_start>yes</run_on_start>
<log_analytics>
      <auth_path>[credentials path]</auth_path>
      <tenantdomain>[tenant]</tenantdomain>
      <request>
          <query>SigninLogs</query>
          <workspace>[workspace id]</workspace>
          <time_offset>7d</time_offset>
      </request>
  </log_analytics>
</wodle> ```
For more details on configuring Wazuh with Azure Log Analytics check https://documentation.wazuh.com/current/azure/activity-services/services/log-analytics.html


## Schema

| Field | Description | Type |
|---|---|---|
| azure.signinlogs.resource_id | The identifier of the resource that the user signed in to | keyword |
| azure.signinlogs.properties.created_at | Date and time (UTC) the sign-in was initiated
 | keyword |
| azure.signinlogs.properties.processing_time_ms | Processing time in milliseconds
 | float |
| azure.signinlogs.properties.risk_level_during_signin | Risk level during signIn
 | keyword |
| azure.signinlogs.properties.status.error_code | Error code
 | long |
| azure.signinlogs.properties.status.additional_details | Additional details
 | keyword |
| azure.signinlogs.properties.authentication_processing_details | Additional authentication processing details, such as the agent name in case of PTA/PHS or Server/farm name in case of federated authentication.
 | keyword |
| azure.signinlogs.identity | Identity | keyword |
| azure.signinlogs.properties.app_display_name | App display name
 | keyword |
| azure.signinlogs.properties.app_id | App ID
 | keyword |
| azure.signinlogs.properties.client_app_used | Client app used
 | keyword |
| azure.signinlogs.properties.conditional_access_status | Conditional access status
 | keyword |
| azure.signinlogs.properties.device_detail | Device detail | keyword |
| azure.signinlogs.properties.id | Unique ID representing the sign-in activity
 | keyword |
| azure.signinlogs.properties.is_interactive | Is interactive
 | boolean |
| azure.signinlogs.properties.original_request_id | Original request ID
 | keyword |
| azure.signinlogs.properties.risk_detail | Risk detail
 | keyword |
| azure.signinlogs.properties.risk_level_aggregated | Risk level aggregated
 | keyword |
| azure.signinlogs.properties.risk_state | Risk state
 | keyword |
| azure.signinlogs.properties.service_principal_id | The application identifier used for sign-in. This field is populated when you are signing in using an application.
 | keyword |
| azure.signinlogs.properties.parsed_status | Status
 | object |
| azure.signinlogs.properties.token_issuer_name | Token issuer name
 | keyword |
| azure.signinlogs.properties.token_issuer_type | Token issuer type
 | keyword |
| azure.signinlogs.properties.user_display_name | User display name
 | keyword |
| azure.signinlogs.properties.user_id | User ID
 | keyword |
| azure.signinlogs.properties.user_principal_name | User principal name
 | keyword |
| azure.signinlogs.result_description | Result description
 | keyword |
| azure.signinlogs.result_signature | Result signature
 | keyword |
| azure.signinlogs.result_type | Result type | keyword |
## Decoders

| Name | Description |
|---|---|
| decoder/azure-SignInLogs/0 | Decoder for Azure SignInLogs events |
## Changelog

| Version | Description | Details |
|---|---|---|
| 1.0.0-dev | Created Azure SignInLogs integration | [#16676](#) |
