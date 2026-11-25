using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace portGate.Core;

public sealed class Config
{
    public int SchemaVersion { get; set; } = 1;
    public string ServerId { get; set; } = Guid.NewGuid().ToString("N");
    public int UdpPort { get; set; } = 51888;
    public string ListenAddress { get; set; } = "::";
    public string ServerAddress { get; set; } = "";
    public int RdpPort { get; set; }
    public bool AllowUdpRdp { get; set; } = true;
    public string[] TrustedRdpCidrs { get; set; } = [];
    public string[] AllowedKnockCidrs { get; set; } = [];
    public int LeaseSeconds { get; set; } = 300;
    public int MaxLeaseSeconds { get; set; } = 86400;
    public const int LeaseLimitSeconds = 7 * 86400;
    public int ChallengeSeconds { get; set; } = 30;
    public int MaxClients { get; set; } = 100;
    public int MaxRequests { get; set; } = 2000;
    public int MaxLeases { get; set; } = 500;
    public void Validate(bool allowLegacyUnrestrictedRdp = false)
    {
        if (SchemaVersion != 1 || !Protocol.ValidId(ServerId)) throw new InvalidDataException("Некорректная версия или serverId.");
        if (UdpPort is < 1024 or > 65535 || RdpPort is < 0 or > 65535 || UdpPort == RdpPort) throw new InvalidDataException("Некорректные порты.");
        _ = IPAddress.Parse(ListenAddress);
        if (ServerAddress.Length != 0) AccessExport.ValidateServer(ServerAddress);
        if (LeaseSeconds < 30 || LeaseSeconds > MaxLeaseSeconds || MaxLeaseSeconds > LeaseLimitSeconds || ChallengeSeconds is < 5 or > 30)
            throw new InvalidDataException("Некорректные временные ограничения.");
        if (MaxClients is < 1 or > 1000 || MaxRequests is < 10 or > 10000 || MaxLeases is < 1 or > 5000) throw new InvalidDataException("Некорректные ограничения ресурсов.");
        if (TrustedRdpCidrs.Length > 256 || AllowedKnockCidrs.Length > 256) throw new InvalidDataException("Слишком много подсетей.");
        foreach (var cidr in TrustedRdpCidrs.Concat(AllowedKnockCidrs)) _ = Cidr.Parse(cidr);
        if (!allowLegacyUnrestrictedRdp && Cidr.CoversAddressFamily(TrustedRdpCidrs.Select(Cidr.Parse)))
            throw new InvalidDataException("Постоянный белый список RDP не может охватывать все адреса IPv4 или IPv6.");
    }
}
public sealed class ClientRecord
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string Name { get; set; } = "";
    public string ProtectedKey { get; set; } = "";
    public DateTimeOffset Created { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? Expires { get; set; }
    public bool Enabled { get; set; } = true;
    public int LeaseSeconds { get; set; } = 300;
    public DateTimeOffset? LastRequest { get; set; }
    public string? LastIp { get; set; }
    public bool Active(DateTimeOffset now) => Enabled && (Expires == null || Expires > now);
}
public sealed class Lease
{
    public string RuleId { get; set; } = "";
    public string ClientId { get; set; } = "";
    public string Ip { get; set; } = "";
    public DateTimeOffset Expires { get; set; }
    public string Phase { get; set; } = "Prepared";
}
public sealed class RequestRecord
{
    public string ClientId { get; set; } = "";
    public string Nonce { get; set; } = "";
    public string Ip { get; set; } = "";
    public string Challenge { get; set; } = "";
    public long ChallengeExpires { get; set; }
    public long RetainUntil { get; set; }
    public string? LeaseId { get; set; }
    public string? Result { get; set; }
}
public sealed class State
{
    public int SchemaVersion { get; set; } = 1;
    public List<ClientRecord> Clients { get; set; } = [];
    public List<Lease> Leases { get; set; } = [];
    public List<RequestRecord> Requests { get; set; } = [];
    public Migration? Migration { get; set; }
}
public sealed class Migration
{
    public string Generation { get; set; } = Guid.NewGuid().ToString("N");
    public DateTimeOffset Started { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset RollbackAt { get; set; } = DateTimeOffset.UtcNow.AddSeconds(120);
    public bool Confirmed { get; set; }
    public bool Applying { get; set; }
    public bool Restoring { get; set; }
    public string[] RestoreProblems { get; set; } = [];
    public int InitialSession { get; set; }
    public Config Config { get; set; } = new();
    public List<FirewallRule> DisabledRules { get; set; } = [];
}
public sealed record Cidr(IPAddress Network, int Prefix)
{
    public static bool CoversAddressFamily(IEnumerable<Cidr> addresses)
    {
        var prefixes = new HashSet<string>(StringComparer.Ordinal);
        foreach (var address in addresses)
        {
            var prefix = address;
            while (prefix.Prefix > 0 && prefixes.Add(prefix.Canonical))
            {
                int bit = prefix.Prefix - 1;
                byte[] sibling = prefix.Network.GetAddressBytes();
                sibling[bit / 8] ^= (byte)(128 >> (bit % 8));
                if (!prefixes.Contains(new Cidr(new IPAddress(sibling), prefix.Prefix).Canonical)) break;
                prefix = new Cidr(prefix.Network, bit);
            }
            if (prefix.Prefix == 0) return true;
        }
        return false;
    }
    public string Canonical
    {
        get
        {
            byte[] bytes = Network.GetAddressBytes();
            for (int i = Prefix; i < bytes.Length * 8; i++) bytes[i / 8] &= (byte)~(1 << (7 - i % 8));
            return new IPAddress(bytes).ToString() + "/" + Prefix;
        }
    }
    public static string NormalizeFirewallAddresses(string addresses)
    {
        return string.Join(",", addresses.Split(',').Select(value =>
        {
            value = value.Trim(); if (value == "*") return "*";
            var parts = value.Split('/');
            if (parts.Length == 2 && parts[1].Contains('.') && IPAddress.TryParse(parts[1], out var mask))
            {
                string bits = string.Concat(mask.GetAddressBytes().Select(b => Convert.ToString(b, 2).PadLeft(8, '0')));
                int prefix = bits.TakeWhile(c => c == '1').Count();
                if (bits[prefix..].Contains('1')) throw new FormatException("Некорректная маска брандмауэра.");
                value = parts[0] + "/" + prefix;
            }
            return Parse(value).Canonical;
        }).Order(StringComparer.Ordinal));
    }
    public static Cidr Parse(string value)
    {
        var parts = value.Split('/');
        if (parts.Length > 2) throw new FormatException("Некорректный CIDR.");
        var ip = Normalize(IPAddress.Parse(parts[0]));
        int bits = ip.GetAddressBytes().Length * 8;
        int prefix = parts.Length == 2 ? int.Parse(parts[1], System.Globalization.CultureInfo.InvariantCulture) : bits;
        if (prefix < 0 || prefix > bits) throw new FormatException("Некорректная маска.");
        return new(ip, prefix);
    }
    public static IPAddress Normalize(IPAddress ip) => ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4() : ip;
    public bool Contains(IPAddress value)
    {
        byte[] a = Network.GetAddressBytes(), b = Normalize(value).GetAddressBytes();
        if (a.Length != b.Length) return false;
        for (int i = 0; i < Prefix; i++) if ((a[i / 8] & (1 << (7 - i % 8))) != (b[i / 8] & (1 << (7 - i % 8)))) return false;
        return true;
    }
}
public static class Json
{
    public static readonly JsonSerializerOptions Options = new() { WriteIndented = true, PropertyNameCaseInsensitive = true, PropertyNamingPolicy = JsonNamingPolicy.CamelCase, Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping };
    public static string Write<T>(T value) => JsonSerializer.Serialize(value, Options);
    public static T Read<T>(string value) => JsonSerializer.Deserialize<T>(value, Options) ?? throw new InvalidDataException("Пустой документ.");
}
public static partial class Protocol
{
    [GeneratedRegex("^[a-zA-Z0-9_-]{1,64}$", RegexOptions.CultureInvariant)] private static partial Regex IdRegex();
    public static bool ValidId(string id) => IdRegex().IsMatch(id);
    public static string RandomHex(int bytes = 16) => Convert.ToHexString(RandomNumberGenerator.GetBytes(bytes)).ToLowerInvariant();
    public static string Sign(string body, byte[] key) => Convert.ToHexString(HMACSHA256.HashData(key, System.Text.Encoding.UTF8.GetBytes(body))).ToLowerInvariant();
    public static string Pack(string body, byte[] key) => body + "|" + Sign(body, key);
    public static bool Verify(string packet, byte[] key)
    {
        int split = packet.LastIndexOf('|');
        if (split < 0) return false;
        try { return CryptographicOperations.FixedTimeEquals(Convert.FromHexString(Sign(packet[..split], key)), Convert.FromHexString(packet[(split + 1)..])); }
        catch (FormatException) { return false; }
    }
}
