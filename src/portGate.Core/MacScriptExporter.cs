using System.Globalization;

namespace portGate.Core;

internal static class MacScriptExporter
{
    public static string Render(string server, int port, string serverId, string clientId, byte[] key)
    {
        using var resource = typeof(MacScriptExporter).Assembly.GetManifestResourceStream("portGate.MacClient")
            ?? throw new InvalidDataException("В поставке отсутствует шаблон macOS.");
        using var reader = new StreamReader(resource);
        string perl = reader.ReadToEnd().ReplaceLineEndings("\n")
            .Replace("@@SERVER@@", server, StringComparison.Ordinal)
            .Replace("@@PORT@@", port.ToString(CultureInfo.InvariantCulture), StringComparison.Ordinal)
            .Replace("@@SERVERID@@", serverId, StringComparison.Ordinal)
            .Replace("@@CLIENTID@@", clientId, StringComparison.Ordinal)
            .Replace("@@KEY@@", Convert.ToBase64String(key), StringComparison.Ordinal);

        // The address and IDs have already been validated. Quote the full Perl program separately for AppleScript.
        return Wrapper.Replace("@@PROGRAM@@", Quote(perl), StringComparison.Ordinal)
            .Replace("@@ADDRESS@@", Quote(server), StringComparison.Ordinal)
            .Replace("@@UDP@@", port.ToString(CultureInfo.InvariantCulture), StringComparison.Ordinal)
            .ReplaceLineEndings("\n") + "\n";
    }

    private static string Quote(string text) => "\"" + text.Replace("\\", "\\\\", StringComparison.Ordinal)
        .Replace("\"", "\\\"", StringComparison.Ordinal).Replace("\n", "\\n", StringComparison.Ordinal) + "\"";

    private const string Wrapper = """
        use AppleScript version "2.4"
        use framework "Foundation"
        use scripting additions

        -- Персональный пропуск portGate. Передавайте только владельцу.
        on run
            set hostName to @@ADDRESS@@
            set authEndpoint to hostName & " / UDP @@UDP@@"
            set fileManager to current application's NSFileManager's defaultManager()
            if not ((fileManager's isExecutableFileAtPath:"/usr/bin/perl") as boolean) then
                display alert "Для этого пропуска нужен системный Perl" message "В этой установке macOS отсутствует /usr/bin/perl. Обратитесь к администратору."
                return
            end if

            set clientProgram to @@PROGRAM@@
            set inputPipe to current application's NSPipe's pipe()
            set outputPipe to current application's NSPipe's pipe()
            set child to current application's NSTask's alloc()'s init()
            child's setLaunchPath:"/usr/bin/perl"
            child's setArguments:{"-"}
            child's setStandardInput:inputPipe
            child's setStandardOutput:outputPipe
            child's setStandardError:outputPipe
            set writer to inputPipe's fileHandleForWriting()
            try
                -- Send the key and program through a pipe, without files or process arguments.
                child's |launch|()
                set sourceString to current application's NSString's stringWithString:clientProgram
                writer's writeData:(sourceString's dataUsingEncoding:(current application's NSUTF8StringEncoding))
                writer's closeFile()
                set outputReader to outputPipe's fileHandleForReading()
                set resultData to outputReader's readDataToEndOfFile()
                child's waitUntilExit()
                set resultString to current application's NSString's alloc()'s initWithData:resultData encoding:(current application's NSUTF8StringEncoding)
                if resultString is missing value then error "Некорректный ответ"
                set trimmedResult to resultString's stringByTrimmingCharactersInSet:(current application's NSCharacterSet's whitespaceAndNewlineCharacterSet())
                set resultText to trimmedResult as text
                set exitStatus to child's terminationStatus() as integer
            on error
                try
                    writer's closeFile()
                end try
                if (child's isRunning() as boolean) then child's terminate()
                display alert "Не удалось запустить авторизацию portGate" message authEndpoint
                return
            end try

            if exitStatus is 0 and resultText starts with "KG_OK|" then
                set parts to (trimmedResult's componentsSeparatedByString:"|") as list
                if (count of parts) is 4 then
                    set grantedUntil to item 2 of parts as text
                    set targetAddress to item 3 of parts as text
                    set rdpPort to item 4 of parts as text
                    if targetAddress is "" then set targetAddress to hostName
                    if targetAddress contains ":" then set targetAddress to "[" & targetAddress & "]"
                    set rdpEndpoint to targetAddress & ":" & rdpPort
                    set answer to display dialog "Доступ открыт до " & grantedUntil & " по местному времени." & return & "Сервер: " & hostName & return & "Адрес для RDP-клиента: " & rdpEndpoint with title "portGate" buttons {"Скопировать адрес", "OK"} default button "OK"
                    if button returned of answer is "Скопировать адрес" then set the clipboard to rdpEndpoint
                    return
                end if
            end if

            if resultText is "KG_DNS" then
                set failureText to "Не удалось определить сетевой адрес сервера."
            else if resultText is "KG_CHALLENGE" then
                set failureText to "Сервер не прислал первый подписанный ответ. Проверьте доступность UDP-порта и действует ли ключ."
            else if resultText is "KG_RESULT" then
                set failureText to "Не получено подписанное подтверждение открытия RDP."
            else
                set failureText to "Не удалось выполнить авторизацию. Проверьте наличие системного Perl и его стандартных модулей."
            end if
            display alert "Доступ RDP не подтверждён" message (failureText & return & authEndpoint)
        end run
        """;
}
