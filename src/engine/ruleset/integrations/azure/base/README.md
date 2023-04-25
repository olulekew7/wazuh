# Azure Integration


|   |   |
|---|---|
| event.module | azure |

This integration processes events logs from Azure

## Compatibility

Base decoder for Azure integration

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
      <request>
          <query>SigninLogs</query>
          <workspace>[workspace id]</workspace>
          <time_offset>7d</time_offset>
      </request>
<request>
          <query>AuditLogs</query>
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
| azure.resource.id | The identifier of the resource that the user signed in to. | keyword |
| azure.subscription_id | Azure subscription ID
 | keyword |
| azure.resource.group | Resource group
 | keyword |
| azure.resource.provider | Resource type/namespace
 | keyword |
| azure.tenant_id | Tenant ID | keyword |
## Decoders

| Name | Description |
|---|---|
| decoder/azure-decoder/0 | Parent decoder for Azure events |
## Changelog

| Version | Description | Details |
|---|---|---|
| 1.0.0-dev | Created Azure  integration | [#16676](#) |
