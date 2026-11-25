using System.Security.Cryptography;
using System.Text;

namespace portGate.Core;
public static class ScriptExporter
{
    public static string Export(Store store, string id, string server, bool launchRdp, string format = "bat")
    {
        if (format is not ("bat" or "ps1" or "applescript")) throw new ArgumentException("Выберите формат bat, ps1 или applescript.");
        using var guard = store.Lock(); var config = store.Config(); var state = store.Load();
        id = AccessExport.ParseClientId(id);
        server = string.IsNullOrWhiteSpace(server) ? config.ServerAddress : server.Trim();
        AccessExport.ValidateServer(server);
        var client = state.Clients.SingleOrDefault(c => c.Id == id) ?? throw new InvalidOperationException("Клиент доступа не найден.");
        if (!client.Enabled) throw new InvalidOperationException("Доступ клиента отозван. Перевыпустите ключ перед сохранением скрипта.");
        if (!client.Active(DateTimeOffset.UtcNow)) throw new InvalidOperationException("Срок действия ключа истёк. Измените срок перед сохранением скрипта.");
        byte[] key = Native.Unprotect(client.ProtectedKey);
        try
        {
            if (!Protocol.ValidId(config.ServerId)) throw new InvalidDataException("Некорректный идентификатор сервера.");
            if (format == "applescript") return MacScriptExporter.Render(server, config.UdpPort, config.ServerId, client.Id, key);
            string template = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Templates", "knock.ps1"));
            string script = template.Replace("@@SERVER@@", server).Replace("@@PORT@@", config.UdpPort.ToString(System.Globalization.CultureInfo.InvariantCulture)).Replace("@@SERVERID@@", config.ServerId).Replace("@@CLIENTID@@", client.Id).Replace("@@KEY@@", Convert.ToBase64String(key)).Replace("@@LAUNCH@@", launchRdp ? "$true" : "$false");
            return format == "ps1" ? script : WrapBatch(script, showSuccess: !launchRdp);
        }
        finally { CryptographicOperations.ZeroMemory(key); }
    }

    // The key and all profile data live in a non-executed base64 payload, never cmd syntax or process arguments.
    public static string WrapBatch(string script, bool showSuccess = false)
    {
        const string bootstrap = "try { $ErrorActionPreference='Stop'; if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') { throw 'PowerShell language restrictions prevent this client. Contact your administrator.' }; Import-Module ($PSHOME+'\\Modules\\Microsoft.PowerShell.Security\\Microsoft.PowerShell.Security.psd1') -ErrorAction Stop; $p=Get-ExecutionPolicy; if ($p -in @('Restricted','AllSigned')) { throw ('Execution policy '+$p+' prevents this unsigned client. Contact your administrator.') }; if ($p -eq 'RemoteSigned') { $zone=Get-Content -LiteralPath $env:KG_SELF -Stream Zone.Identifier -ErrorAction SilentlyContinue; if (($zone -join [char]10) -match 'ZoneId=[3-4]') { throw 'Downloaded unsigned client is restricted by RemoteSigned. Contact your administrator.' } }; $raw=[IO.File]::ReadAllText($env:KG_SELF); $marker='::KG_PAYLOAD_BASE64:'; $i=$raw.LastIndexOf($marker,[StringComparison]::Ordinal); if($i -lt 0){throw 'Client payload is missing.'}; $code=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($raw.Substring($i+$marker.Length).Trim())); $global:LASTEXITCODE=0; & ([ScriptBlock]::Create($code)); exit $LASTEXITCODE } catch { [Console]::Error.WriteLine('portGate: '+$_.Exception.Message); exit 1 }";
        string header = """
@echo off
setlocal DisableDelayedExpansion
title portGate Access
echo [1/4] Checking Windows PowerShell environment...
set "KG_SELF=%~f0"
set "KG_PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if not exist "%KG_PS%" goto kg_missing
"%KG_PS%" -NoLogo -NoProfile -Command "@@BOOTSTRAP@@"
set "KG_RC=%ERRORLEVEL%"
if "%KG_RC%"=="0" goto kg_success
echo.
echo portGate failed. Review the error above.
echo Press any key to close this window.
pause >nul
exit /b %KG_RC%
:kg_missing
echo Windows PowerShell was not found. Contact your administrator.
echo Press any key to close this window.
pause >nul
exit /b 2
:kg_success
@@SUCCESS@@
exit /b 0
::KG_PAYLOAD_BASE64:
""";
        return header.Replace("@@BOOTSTRAP@@", bootstrap)
            .Replace("@@SUCCESS@@", showSuccess ? "\"%SystemRoot%\\System32\\timeout.exe\" /t 5 >nul 2>&1" : "")
            .ReplaceLineEndings("\r\n") + "\r\n" + Convert.ToBase64String(Encoding.UTF8.GetBytes(script)) + "\r\n";
    }
}
