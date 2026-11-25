# portGate

[Русский](README.md) · English

portGate limits network access to Remote Desktop on Windows Server. It adapts *port knocking* by authenticating each access request with a personal key.

The user runs a client script once. The script sends a signed request. The server looks up the key associated with the access pass and sends a fresh challenge. The script signs the challenge with the same key. This proves that the client holds the key during the current exchange. A captured response from a previous exchange cannot open a new access window.

After verifying the response, portGate adds a temporary Windows Firewall rule for new RDP connections from the client's IP address. The rule is removed when the access window expires. Windows credentials, RDP permissions, and Network Level Authentication (NLA) still apply.

- The **server and management panel** run on Windows Server 2016, 2019, or 2022, x64. See [validation](docs/validation.en.md) for the scope of testing.
- **Windows access passes** use `.bat` or `.ps1` with Windows PowerShell 5.1. **macOS access passes** use a personal `.applescript` or a `.scpt` saved from it. Each exported file contains an access key.
- **[Download portGate for Windows x64](https://github.com/ofdistress2/portGate/releases/latest).** The self-contained build includes the .NET runtime.

## Install

1. Arrange console access to the server and a way to restore the original firewall rules. For a VM, take a snapshot.
2. Verify the ZIP's SHA-256 against the file attached to the release. Extract the entire archive, launch `portgate.Manager.exe`, and select **Install**.
3. Configure trusted management addresses and review the firewall plan. After applying it, confirm access from a **new** RDP session originating from an allowlisted IP address. Without confirmation, portGate rolls back the changes.
4. Create personal access passes and share them privately with their owners.

The [administrator guide](docs/admin-guide.en.md) covers upgrades, command-line use, client passes, and [firewall recovery](docs/admin-guide.en.md#stop-restore-or-uninstall). If both the service and Task Scheduler are unavailable, temporary rules can remain active past their expected expiry.

## Validation

Version 1.0.11 completed a two-day pilot on a live Windows RDP server. The pilot covered installation, stopping, restarting, and rollback. See the [validation report](docs/validation.en.md) for details.

## Build from source

Use the .NET 10 SDK on Windows. The first restore needs access to NuGet.

```powershell
.\build.ps1
.\build.ps1 -Publish -SelfContained -Package
```

Starting with 1.0.12, the panel opens in English. To switch to Russian, open **Settings** → **Interface language**, choose Russian, and click **Apply language**. The panel remembers the choice for the current Windows account.

The first command builds the solution and runs the tests, including a Windows PowerShell 5.1 UDP loopback test. The second also builds the self-contained package and writes its ZIP and SHA-256 file to `publish`.

[Contributing](CONTRIBUTING.md#contributing) · [Report a vulnerability](SECURITY.md#reporting-a-vulnerability) · [MIT License](LICENSE)
