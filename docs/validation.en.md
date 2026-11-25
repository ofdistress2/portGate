# portGate 1.0.11 validation

[Русский](validation.md) · English

## Two-day pilot

Version 1.0.11 was deployed to a live Windows RDP server and remains in use. The pilot covered installation, stopping, restarting, and rollback on that server.

## Build and tests

`build.ps1` tests state storage, the authorization exchange, and firewall planning and rollback with a simulated firewall. It also runs the generated Windows PowerShell 5.1 client against a real UDP loopback endpoint.

## Additional environments

Windows Server 2016, 2019, and 2022 are target platforms. The [VM test matrix in Russian](vm-acceptance.md) covers Server Core, Group Policy, failures, and upgrades.

macOS uses a client access pass. The Windows test suite checks that the pass is generated correctly. Compile the `.applescript` to a `.scpt` and run it in Script Editor on the target macOS version to validate that environment.
