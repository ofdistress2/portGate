# portGate administrator guide

[Русский](admin-guide.md) · English

Download the Windows x64 archive from the [latest release](https://github.com/ofdistress2/portGate/releases/latest). The management panel opens in English. You can change the display language under **Settings → Interface language**.

Starting with 1.0.13, the installation paths and service name use `portgate`. If you use the old `KnockGate` service from 1.0.11 or 1.0.12, migrate its data and retire it during a maintenance window with console access.

## Install and configure on a test server

1. Arrange console access and save the current firewall rules. Take a snapshot if the server is a VM.
2. Extract the entire ZIP to a separate directory. Run `portgate.Manager.exe` with elevation and select **Install**. The installer uses the package manifest to copy the application into `C:\Program Files\portgate`. It registers the Windows service and maintenance tasks. Firewall changes are applied in a separate step.
3. In **Settings**, set the trusted management addresses, UDP authorization port, the public IP address or DNS name clients will use, and the allowed access duration. An IPv6 listen address of `::` enables dual-stack IPv4 and IPv6.
4. Start the service and review the plan. Resolve any Group Policy conflict, overly broad rule, or firewall policy that the plan could not evaluate. Apply the plan with **Apply protection**. The automatic rollback timer is 120 seconds.
5. From a trusted address, open a **new** RDP session and confirm from that session. Reconnecting to an existing session retains its ID and cannot confirm the change. If confirmation is missing, the scheduled rollback restores the previous rules.
6. After confirmation, create personal client passes and transfer them privately.

To upgrade, close the installed panel, extract the new archive to a separate directory, and select **Install** in the new panel. The existing `%ProgramData%\portgate` directory and its clients and keys are reused. The Windows service name is `portgate`.

The service periodically validates the firewall policy before granting new access. It checks approximately every 30 seconds. Existing grants expire or can be revoked independently. While a grant is valid, clients can reconnect from the same IP without rerunning the script. A change of IP requires a new authorization.

## Command line

Run the following commands in an elevated PowerShell session from the extracted archive.

```powershell
.\portgate.Host.exe install
.\portgate.Host.exe config
# Save the configuration as JSON and set trustedRdpCidrs.
.\portgate.Host.exe config-save C:\Admin\config.json
.\portgate.Host.exe start
.\portgate.Host.exe plan
.\portgate.Host.exe apply
# In a new RDP session from a trusted address:
.\portgate.Host.exe confirm
.\portgate.Host.exe clients create 'Administrator laptop' 300
.\portgate.Host.exe clients export CLIENT_ID rdp.example.com C:\Admin\Access.bat true
.\portgate.Host.exe clients list
.\portgate.Host.exe clients revoke CLIENT_ID
.\portgate.Host.exe clients rotate CLIENT_ID
.\portgate.Host.exe status
```

`clients export` writes one file containing the key. Re-exporting an active pass uses the existing key. `clients rotate` issues a new key and revokes the previous grants for that client. The access window and key expiry are separate settings. `plan` and `diagnose` read the effective policy. Use `help` for the command list.

## Client access passes

Each exported file is a credential. Share it with its owner and keep it out of issue attachments and diagnostic bundles.

### Windows

Double-click the exported `.bat` to run it with Windows PowerShell 5.1. Administrators can also export a `.ps1` and run it directly.

```powershell
powershell.exe -NoProfile -File .\Access.ps1
# Authorize without starting the RDP client.
powershell.exe -NoProfile -File .\Access.ps1 -NoRdp
```

Downloaded scripts remain subject to Windows PowerShell execution policy and your organization's restrictions. The script reports success after verifying the server's signed confirmation.

### macOS

Export a personal `.applescript` from the Windows panel or with the CLI command below.

```powershell
.\portgate.Host.exe clients export CLIENT_ID rdp.example.com .\portGate-Access.applescript
```

Open the file in Script Editor on the Mac and select **Run**. To save a compiled version, choose the **Script** format (`.scpt`). Both files contain the same access key. The script uses Foundation and the system `/usr/bin/perl` with its standard modules. After the pass reports success, connect with your installed RDP client using the displayed address and port.

## Stop, restore, or uninstall

```powershell
.\portgate.Host.exe stop
.\portgate.Host.exe restore
.\portgate.Host.exe uninstall --restore
# To keep only the permanent allowlist:
.\portgate.Host.exe uninstall --keep-trusted
```

Stopping the service removes temporary grants and keeps the allowlist. Restore reverts changes made by portGate. If an administrator or another tool changed an affected rule in the meantime, resolve the reported conflict manually before proceeding.

After confirming protection, update the addresses in Settings or with `config-save`. Keep at least one IP address or CIDR. PortGate checks and applies the updated list immediately, without restarting the service or requiring another RDP sign-in confirmation. Temporary grants retain their expiry. To change network settings or other firewall settings, restore the previous rules, save the new configuration, restart the service, and apply the new plan.

## Data and limitations

`%ProgramData%\portgate` stores the configuration, state, scheduler XML, and rotating JSONL log. The directory is restricted to SYSTEM and Administrators. Keys use Windows DPAPI machine-scope protection. Issue fresh keys when moving to another machine.

Windows Firewall rules have no built-in expiration. The service and a scheduled cleanup task remove expired rules. If both are unavailable, a temporary rule can outlast its window. Expiration controls new RDP connections. An established RDP session can continue until it ends normally.

If the server is behind NAT, configure the relevant UDP authorization and RDP forwarding on the upstream device. A single external IP can represent multiple devices. Windows credentials, permissions, and NLA continue to govern RDP sign-in.
