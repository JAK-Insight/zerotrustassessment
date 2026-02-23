# Microsoft Cloud Security Benchmark policy initiative is assigned on Azure subscriptions

## Overview

The Microsoft Cloud Security Benchmark (MCSB) is a comprehensive set of security best practices for Azure workloads, aligned with industry standards such as CIS, NIST, and PCI-DSS. When assigned as an Azure Policy initiative, it continuously evaluates your resources against these controls and provides a compliance score in Microsoft Defender for Cloud.

Without MCSB assigned, Defender for Cloud's Regulatory Compliance dashboard will not track posture against this standard, and policy-driven enforcement and alerting for misconfigured resources will not be active.

## How to remediate

MCSB is typically assigned automatically when Microsoft Defender for Cloud is enabled. If it is missing:

1. Open the [Azure portal](https://portal.azure.com) and navigate to **Microsoft Defender for Cloud** > **Environment settings**.
2. Select the subscription or management group.
3. Under **Security policies**, locate **Microsoft Cloud Security Benchmark** and toggle it **On**.

Alternatively, assign the initiative directly via Azure Policy:
1. Navigate to **Azure Policy** > **Definitions**.
2. Search for **Microsoft Cloud Security Benchmark**.
3. Click **Assign** and set the scope to the management group or subscription.

## Learn more

- [Microsoft Cloud Security Benchmark overview](https://learn.microsoft.com/en-us/security/benchmark/azure/introduction)
- [Improve your regulatory compliance](https://learn.microsoft.com/en-us/azure/defender-for-cloud/regulatory-compliance-dashboard)
