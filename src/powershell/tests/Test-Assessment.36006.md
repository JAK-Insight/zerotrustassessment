# Azure subscription activity logs are forwarded to a Log Analytics workspace

## Overview

The Azure subscription Activity Log records all control-plane operations — who created, modified, or deleted resources, when, and from where. Forwarding this log to a Log Analytics workspace is a foundational "Assume Breach" control: it enables security teams to detect unauthorized or suspicious administrative activity, correlate events across services, and retain evidence for incident investigations.

Without a diagnostic setting routing activity logs to Log Analytics, this telemetry is only available for 90 days in the Azure portal and cannot be queried alongside other security data.

## How to remediate

1. Open the [Azure portal](https://portal.azure.com) and select the target subscription.
2. Navigate to **Monitor** > **Activity log** > **Export Activity Logs**.
3. Click **+ Add diagnostic setting**.
4. Select all log categories (Administrative, Security, ServiceHealth, Alert, Recommendation, Policy, Autoscale, ResourceHealth).
5. Under **Destination details**, select **Send to Log Analytics workspace** and choose your workspace.
6. Click **Save**.

Repeat for each subscription. Consider using Azure Policy to enforce this configuration at scale.

## Learn more

- [Send the Activity log to a Log Analytics workspace](https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log?tabs=powershell#send-to-log-analytics-workspace)
- [Azure Monitor diagnostic settings](https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/diagnostic-settings)
