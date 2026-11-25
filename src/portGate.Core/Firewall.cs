using Microsoft.Win32;
using System.Net.NetworkInformation;
using System.Text.Json;

namespace portGate.Core;

public sealed class FirewallRule
{
    public string Id { get; set; } = "";
    public string Source { get; set; } = "Local";
    public string Scope { get; set; } = "";
    public string Package { get; set; } = "";
    public string PackageFamilyName { get; set; } = "";
    public string DynamicTransport { get; set; } = "";
    public string Name { get; set; } = "";
    public string Group { get; set; } = "";
    public string Ports { get; set; } = "";
    public string Remote { get; set; } = "*";
    public string Application { get; set; } = "";
    public string Service { get; set; } = "";
    public int Protocol { get; set; }
    public int Direction { get; set; } = 1;
    public int Action { get; set; } = 1;
    public int Profiles { get; set; } = 7;
    public bool Enabled { get; set; } = true;
    public string Identity => Id.Length == 0 ? Name : Id;
    public string Fingerprint => Json.Write(new { Id, Name = Id.Length == 0 ? Name : "", Group, Ports, Remote, Application = Environment.ExpandEnvironmentVariables(Application).ToUpperInvariant(), Service = Service.ToUpperInvariant(), Protocol, Direction, Action, Profiles, Scope, Package, PackageFamilyName, DynamicTransport });
}
public sealed class FirewallPlan
{
    public int RdpPort { get; set; }
    public List<string> Conflicts { get; set; } = [];
    public List<string> Warnings { get; set; } = [];
    public List<FirewallRule> Disable { get; set; } = [];
    public bool Safe => Conflicts.Count == 0;
}
public interface IFirewall
{
    List<FirewallRule> Rules();
    void Put(FirewallRule rule);
    void Remove(string name);
    void RemoveOwned(IEnumerable<string> names) { foreach (string name in names) Remove(name); }
    void Enable(string name, bool enabled);
    FirewallPlan Plan(Config config);
    FirewallPlan Plan(Config config, CancellationToken cancellationToken) { cancellationToken.ThrowIfCancellationRequested(); return Plan(config); }
    FirewallRule? Find(FirewallRule snapshot) => Rules().SingleOrDefault(r => r.Identity == snapshot.Identity);
}
public sealed class MemoryFirewall : IFirewall
{
    private readonly Dictionary<string, FirewallRule> rules = [];
    public List<FirewallRule> Rules() => rules.Values.ToList();
    public void Put(FirewallRule rule) => rules[rule.Identity] = rule;
    public void Remove(string name) => rules.Remove(name);
    public void Enable(string name, bool enabled) => rules[name].Enabled = enabled;
    public FirewallPlan Plan(Config config) => new() { RdpPort = config.RdpPort == 0 ? 3389 : config.RdpPort, Disable = rules.Values.Where(r => r.Group != WindowsFirewall.Group && r.Enabled && r.Action == 1).ToList() };
}
public sealed class WindowsFirewall : IFirewall
{
    public const string Group = "KnockGate.v1";
    private static dynamic Policy() => Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2")!)!;
    public List<FirewallRule> Rules()
    {
        var result = new List<FirewallRule>();
        foreach (dynamic rule in Policy().Rules)
            result.Add(new() { Name = rule.Name, Group = rule.Grouping ?? "", Ports = rule.Protocol is 6 or 17 ? rule.LocalPorts ?? "*" : "*", Remote = rule.RemoteAddresses ?? "*", Application = rule.ApplicationName ?? "", Service = rule.serviceName ?? "", Protocol = rule.Protocol, Direction = rule.Direction, Action = rule.Action, Profiles = rule.Profiles, Enabled = rule.Enabled });
        return result;
    }
    public void Put(FirewallRule value)
    {
        dynamic rule = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule")!)!;
        rule.Name = value.Name; rule.Description = "Managed by portGate v1"; rule.Grouping = Group;
        rule.Protocol = value.Protocol; rule.LocalPorts = value.Ports; rule.RemoteAddresses = value.Remote;
        rule.Direction = 1; rule.Action = 1; rule.Profiles = 7; rule.Enabled = true;
        Policy().Rules.Add(rule);
    }
    public void Remove(string name)
    {
        RemoveOwned([name]);
    }
    public void RemoveOwned(IEnumerable<string> names)
    {
        var wanted = names.ToHashSet(StringComparer.Ordinal);
        if (wanted.Count == 0) return;
        dynamic rules = Policy().Rules;
        var removable = new List<string>();
        foreach (dynamic rule in rules)
            if (rule.Grouping == Group && wanted.Contains((string)rule.Name)) removable.Add(rule.Name);
        foreach (string name in removable) rules.Remove(name);
    }
    public void Enable(string name, bool enabled)
    {
        if (!name.StartsWith("net:", StringComparison.Ordinal)) { Policy().Rules.Item(name).Enabled = enabled; return; }
        string id = Quote(name[4..]);
        Native.PowerShell("$rules=@(Get-NetFirewallRule -PolicyStore PersistentStore | Where-Object {$_.Name -ceq " + id + "}); if($rules.Count -ne 1){throw 'Rule identity is not unique'}; $rules[0] | Set-NetFirewallRule -Enabled " + (enabled ? "True" : "False"));
    }
    public FirewallRule? Find(FirewallRule snapshot)
    {
        if (snapshot.Id.Length == 0) return Rules().SingleOrDefault(r => r.Name == snapshot.Name);
        string data = Native.PowerShell(NetSecurityProjection.Script + "; $items=@(Get-NetFirewallRule -PolicyStore PersistentStore | Where-Object {$_.Name -ceq " + Quote(snapshot.Id[4..]) + "} | ForEach-Object { Convert-KgRule $_ }); ConvertTo-Json -InputObject $items -Depth 10 -Compress");
        var result = Json.Read<List<FirewallRule>>(data).SingleOrDefault();
        if (result != null) NetSecurityProjection.EnrichLocalConstraints([result]);
        return result;
    }
    private static string Quote(string value) => "'" + value.Replace("'", "''") + "'";
    public FirewallPlan Plan(Config config)
        => Plan(config, CancellationToken.None);
    public FirewallPlan Plan(Config config, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var result = new FirewallPlan();
        int port = Convert.ToInt32(Registry.GetValue(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", "PortNumber", 3389));
        result.RdpPort = config.RdpPort == 0 ? port : config.RdpPort;
        if (result.RdpPort != port) result.Conflicts.Add("Порт конфигурации не совпадает с портом RDP в реестре.");
        if (result.RdpPort == config.UdpPort) result.Conflicts.Add("Порты RDP и авторизации совпадают.");
        if (!IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners().Any(x => x.Port == result.RdpPort)) result.Conflicts.Add("Нет TCP-слушателя на порту RDP.");
        using (var listeners = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations"))
            if (listeners != null && listeners.GetSubKeyNames().Any(n => n != "RDP-Tcp" && n != "Console" && listeners.OpenSubKey(n)?.GetValue("PortNumber") != null)) result.Conflicts.Add("Обнаружен дополнительный listener. Требуется ручная проверка.");
        dynamic policy = Policy();
        foreach (int profile in new[] { 1, 2, 4 })
        {
            if (!policy.FirewallEnabled[profile] || policy.DefaultInboundAction[profile] != 0 || policy.BlockAllInboundTraffic[profile]) result.Conflicts.Add($"Профиль {profile}: брандмауэр отключён, входящие разрешены или включена полная блокировка.");
        }
        if (policy.LocalPolicyModifyState != 0) result.Conflicts.Add("Локальная политика не может быть применена.");
        // ActiveStore provides effective rules AND their origin; unknown conditions fail closed.
        string script = NetSecurityProjection.Script + $"; $kgPort={result.RdpPort}; $kgAuthPort={config.UdpPort}; " +
            """
            $activeRules=@(Get-NetFirewallRule -PolicyStore ActiveStore -TracePolicyStore | Where-Object {$_.Enabled -eq 'True' -and $_.Direction -eq 'Inbound'})
            Initialize-KgFilters 'ActiveStore' $activeRules
            $active=@($activeRules | ForEach-Object { Convert-KgRule $_ })
            $ids=@{}
            foreach($r in $active){if($r.Action -eq 1 -and $r.Source -eq 'Local'){$ids[$r.id]=$true}}
            $local=@()
            if($ids.Count -gt 0){
                $localRules=@(Get-NetFirewallRule -PolicyStore PersistentStore | Where-Object {$ids.ContainsKey('net:'+[string]$_.Name)})
                Initialize-KgFilters 'PersistentStore' $localRules
                $local=@($localRules | ForEach-Object { Convert-KgRule $_ })
            }
            [pscustomobject]@{Active=$active;Local=$local} | ConvertTo-Json -Depth 10 -Compress
            """;
        try
        {
            string data = Native.PowerShell(script, 60000, cancellationToken).Trim();
            var snapshot = Json.Read<PolicySnapshot>(data);
            NetSecurityProjection.EnrichLocalConstraints(snapshot.Active.Concat(snapshot.Local));
            FirewallClassifier.Analyze(snapshot.Active, snapshot.Local, result, config.TrustedRdpCidrs);
            FirewallClassifier.AnalyzeAuthorization(snapshot.Active, config, result);
            // Policy rule merging must not disable local exceptions on any profile.
            foreach (string profile in new[] { "DomainProfile", "StandardProfile", "PublicProfile" })
                if (Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\" + profile, "AllowLocalPolicyMerge", null) is int merge && merge == 0) result.Conflicts.Add("GPO запрещает локальные разрешения: " + profile);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception e) { result.Conflicts.Add("Не удалось подтвердить эффективную политику: " + e.GetType().Name); }
        return result;
    }
}
