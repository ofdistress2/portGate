namespace portGate.Host;

internal static class CommandArguments
{
    internal static void Validate(string command, int count, bool fromConsole = false)
    {
        string? usage = command switch
        {
            "config-save" when count < 1 => "config-save FILE.json",
            "lease-revoke" when count != 1 => "lease-revoke ID",
            "clients-create" when count < 2 => "clients create NAME SECONDS [EXPIRY_ISO8601]",
            "clients-edit" when count < 2 => "clients edit ID NAME [EXPIRY_ISO8601]",
            "clients-revoke" when count < 1 => "clients revoke ID",
            "clients-rotate" when count < 1 => "clients rotate ID",
            "clients-export" when fromConsole && count < 3 => "clients export ID SERVER OUTPUT.bat|OUTPUT.ps1|OUTPUT.applescript [true]",
            "clients-export" when count < 2 => "clients export ID SERVER",
            _ => null
        };
        if (usage is not null) throw new ArgumentException("Использование: " + usage);
    }
}
