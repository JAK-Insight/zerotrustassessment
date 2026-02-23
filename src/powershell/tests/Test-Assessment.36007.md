# Just-In-Time VM access is configured for virtual machines

## Overview

Just-In-Time (JIT) VM access is a Microsoft Defender for Cloud feature that eliminates standing network access to management ports (RDP on port 3389, SSH on port 22, WinRM on ports 5985/5986) on Azure virtual machines. When JIT is enabled, these ports are locked by default in the Network Security Group. Access is granted only when explicitly requested, for a defined time window, to a specific source IP address.

Without JIT, management ports are permanently open to anyone who can reach the VM, making them a prime target for brute-force attacks and exploitation of known vulnerabilities.

## How to remediate

1. Ensure **Microsoft Defender for Servers** is enabled on the subscription (Test 36001).
2. Open the [Azure portal](https://portal.azure.com) and navigate to **Microsoft Defender for Cloud** > **Workload protections** > **Just-in-time VM access**.
3. Under the **Not configured** tab, select the VMs to protect.
4. Click **Enable JIT on selected VMs** and review the default port configuration (RDP, SSH, WinRM).
5. Click **Save**.

Repeat for all subscriptions with virtual machines.

## Learn more

- [Understanding just-in-time (JIT) VM access](https://learn.microsoft.com/en-us/azure/defender-for-cloud/just-in-time-access-overview)
- [Enable just-in-time access on VMs](https://learn.microsoft.com/en-us/azure/defender-for-cloud/just-in-time-access-usage)
