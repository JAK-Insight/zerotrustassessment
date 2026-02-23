# Log Analytics workspaces retain data for at least 90 days

## Overview

Log Analytics workspaces store security telemetry, audit logs, and monitoring data used for threat detection, incident response, and compliance reporting. Retaining data for at least 90 days ensures that security teams have sufficient historical context to investigate incidents, identify attack patterns, and meet regulatory requirements.

A retention period below 90 days may result in the loss of critical forensic evidence during a security investigation.

## How to remediate

1. Open the [Azure portal](https://portal.azure.com) and navigate to **Log Analytics workspaces**.
2. Select a workspace with insufficient retention.
3. Under **Settings**, select **Usage and estimated costs**.
4. Set **Data retention** to **90 days** or more.
5. Click **OK** to save.

Alternatively, use Azure Policy to enforce a minimum retention period across all workspaces.

## Learn more

- [Manage data retention in a Log Analytics workspace](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/data-retention-configure)
- [Azure Monitor Logs overview](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/data-platform-logs)
