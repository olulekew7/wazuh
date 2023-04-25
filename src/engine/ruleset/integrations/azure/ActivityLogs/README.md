# Azure Integration ActivityLogs


|   |   |
|---|---|
| event.module | azure-activitylogs |

This integration processes events logs from Azure

## Compatibility

ActivityLogs decoder for Azure integration

## Configuration

This integration works using Wazuh Log Analytics with Azure. Use this wodle to collect Azure Log Analitycs logs
```html <wodle name="azure-logs">
  <disabled>no</disabled>
  <run_on_start>yes</run_on_start>
<log_analytics>
      <auth_path>[credentials path]</auth_path>
      <tenantdomain>[tenant]</tenantdomain>
      <request>
          <query>AzureActivity</query>
          <workspace>[workspace id]</workspace>
          <time_offset>7d</time_offset>
      </request>
  </log_analytics>
</wodle>
```
For more details on configuring Wazuh with Azure Log Analytics check https://documentation.wazuh.com/current/azure/activity-services/services/log-analytics.html


## Schema

| Field | Description | Type |
|---|---|---|
| azure.activitylogs.properties | Properties | keyword |
| azure.activitylogs.operation_name | Operation name
 | keyword |
| azure.activitylogs.operation_version | Operation version
 | keyword |
| azure.activitylogs.tenant_id | Tenant ID
 | keyword |
| azure.activitylogs.level | Level
 | long |
| azure.activitylogs.result_signature | Result signature
 | keyword |
| azure.activitylogs.event_category | Event Category | keyword |
## Decoders

| Name | Description |
|---|---|
| decoder/azure-ActivityLogs/0 | ActivityLog decoder for Azure events |
## Changelog

| Version | Description | Details |
|---|---|---|
| 1.0.0-dev | Created Azure ActivityLogs integration | [#16676](#) |
