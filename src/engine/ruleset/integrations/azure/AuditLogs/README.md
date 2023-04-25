# Azure Integration - AuditLogs


|   |   |
|---|---|
| event.module | azure-auditlogs |

This integration processes events logs from Azure

## Compatibility

AuditLogs decoder for Azure integration

## Configuration

This integration works using Wazuh Log Analytics with Azure. Use this wodle to collect Azure Log Analitycs logs
```html <wodle name="azure-logs">
  <disabled>no</disabled>
  <run_on_start>yes</run_on_start>
<log_analytics>
      <auth_path>[credentials path]</auth_path>
      <tenantdomain>[tenant]</tenantdomain>
<request>
          <query>AuditLogs</query>
          <workspace>[workspace id]</workspace>
          <time_offset>7d</time_offset>
      </request>
  </log_analytics>
</wodle> ```
For more details on configuring Wazuh with Azure Log Analytics check https://documentation.wazuh.com/current/azure/activity-services/services/log-analytics.html


## Schema

## Decoders

| Name | Description |
|---|---|
| decoder/azure-AuditLogs/0 | AuditLog decoder for Azure events |
## Changelog

| Version | Description | Details |
|---|---|---|
| 1.0.0-dev | Created Azure AuditLogs integration | [#16676](#) |
