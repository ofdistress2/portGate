namespace portGate.Core;

public static class AccessExport
{
    public static string ParseClientId(string output)
    {
        string id = output.Trim();
        if (!Protocol.ValidId(id)) throw new InvalidDataException("Хост вернул некорректный идентификатор клиента.");
        return id;
    }

    public static void ValidateServer(string server)
    {
        if (string.IsNullOrWhiteSpace(server) || server.Length > 253 || server.Any(c => !(char.IsAsciiLetterOrDigit(c) || c is '.' or '-' or ':')))
            throw new ArgumentException("Укажите IP или DNS-имя сервера без порта и протокола.");
    }
}
