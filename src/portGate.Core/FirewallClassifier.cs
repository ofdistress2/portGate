namespace portGate.Core;

public sealed class PolicySnapshot
{
    public List<FirewallRule> Active { get; set; } = [];
    public List<FirewallRule> Local { get; set; } = [];
}

/// <summary>Pure classification of effective rules; no firewall mutation or display-name matching.</summary>
public static class FirewallClassifier
{
    private static readonly string[] NonRdpTransports =
        ["ProximityApps", "ProximitySharing", "WifiDirectPrinting", "WifiDirectDisplay", "WifiDirectDevices", "1", "2", "4", "8", "16", "32", "64"];
    public static void AnalyzeAuthorization(IEnumerable<FirewallRule> active, Config config, FirewallPlan plan)
    {
        var allowed = config.AllowedKnockCidrs.Select(Cidr.Parse).ToArray();
        foreach (var rule in active)
        {
            if (!rule.Enabled || rule.Direction != 1 || rule.Action == 1 || rule.Protocol is not (17 or 256)) continue;
            if (NonRdpTransports.Contains(rule.DynamicTransport, StringComparer.OrdinalIgnoreCase)) continue;
            if (!Any(rule.Service) && !rule.Service.Equals(Deployment.ServiceName, StringComparison.OrdinalIgnoreCase)) continue;
            string program = Environment.ExpandEnvironmentVariables(rule.Application).Trim();
            if (!Any(program) && !Path.GetFileName(program).Equals(Deployment.HostName, StringComparison.OrdinalIgnoreCase)) continue;
            if (rule.Package.Length != 0 && !Any(rule.Package) || rule.PackageFamilyName.Length != 0) continue;
            if (rule.Ports.Split(',').All(port => MatchPort(port.Trim(), config.UdpPort) == PortMatch.No)) continue;
            var blocked = ParseRemoteAddresses(rule.Remote);
            string detail = $"UDP {config.UdpPort}, {rule.Name} [{rule.Id}]. Источники: {rule.Remote}.";
            if (Any(rule.Remote) || blocked == null || Cidr.CoversAddressFamily(blocked))
            {
                plan.Conflicts.Add("Локальная доступность авторизации не подтверждена. " + detail);
                continue;
            }
            if (allowed.Length == 0 || allowed.Any(a => blocked.Any(b => a.Contains(b.Network) || b.Contains(a.Network))))
                plan.Warnings.Add("Точечный запрет UDP-авторизации сохранится. " + detail);
        }
    }

    public static void Analyze(IEnumerable<FirewallRule> active, IReadOnlyCollection<FirewallRule> local, FirewallPlan plan, IReadOnlyCollection<string>? trustedRdpCidrs = null)
    {
        var trusted = (trustedRdpCidrs ?? []).Select(Cidr.Parse).ToArray();
        foreach (var rule in active)
        {
            if (!rule.Enabled || rule.Direction != 1 || rule.Protocol is not (6 or 17 or 256)) continue;
            if (rule.Group == WindowsFirewall.Group) continue;
            if (rule.Package.StartsWith("S-1-15-2-", StringComparison.Ordinal) || System.Text.RegularExpressions.Regex.IsMatch(rule.PackageFamilyName, @"^[a-zA-Z0-9][a-zA-Z0-9.\-]*_[a-zA-Z0-9]{13}$")) continue;
            if (NonRdpTransports.Contains(rule.DynamicTransport, StringComparer.OrdinalIgnoreCase)) continue;
            string app = Environment.ExpandEnvironmentVariables(rule.Application).Trim();
            if (!Any(rule.Service) && !rule.Service.Equals("TermService", StringComparison.OrdinalIgnoreCase)) continue;
            if (!Any(app) && !app.Equals("System", StringComparison.OrdinalIgnoreCase) && !app.EndsWith("\\svchost.exe", StringComparison.OrdinalIgnoreCase) && !app.EndsWith("\\System", StringComparison.OrdinalIgnoreCase)) continue;
            var matches = rule.Ports.Split(',').Select(p => MatchPort(p.Trim(), plan.RdpPort)).ToArray();
            if (!matches.Any(x => x != PortMatch.No)) continue;
            string details = $"{rule.Name} [{rule.Id}] (порты: {rule.Ports}; приложение: {rule.Application}; служба: {rule.Service}; источник: {rule.Source}; динамический транспорт: {rule.DynamicTransport})";
            if (rule.DynamicTransport.Length > 0 && !rule.DynamicTransport.Equals("Any", StringComparison.OrdinalIgnoreCase) && rule.DynamicTransport != "0") { plan.Conflicts.Add("Неизвестный динамический транспорт, требуется проверка: " + details); continue; }
            if (matches.Contains(PortMatch.Unknown)) { plan.Conflicts.Add("Неизвестный фильтр порта, требуется проверка: " + details); continue; }
            if (rule.Action != 1)
            {
                ClassifyBlock(rule, plan, trusted, details);
                continue;
            }
            if (!Any(rule.Remote))
            {
                var sources = ParseRemoteAddresses(rule.Remote);
                if (sources is null)
                {
                    plan.Conflicts.Add($"Не удалось определить источники разрешения RDP: {details} Удалённые адреса: {rule.Remote}.");
                    continue;
                }
                if (!Cidr.CoversAddressFamily(sources))
                {
                    plan.Warnings.Add($"Разрешение RDP для заданных источников сохранится. Доступ для них по этому правилу не требует стука: {details} Удалённые адреса: {rule.Remote}.");
                    continue;
                }
            }
            if (!rule.Source.Equals("Local", StringComparison.OrdinalIgnoreCase)) { plan.Conflicts.Add("Внешняя/доменная политика разрешает RDP: " + details); continue; }
            var candidates = local.Where(r => r.Id.Length != 0 && r.Id == rule.Id).ToList();
            if (candidates.Count != 1) { plan.Conflicts.Add("Локальное правило не найдено по уникальному идентификатору: " + details); continue; }
            var persistent = candidates[0];
            if (persistent.Fingerprint != rule.Fingerprint) { plan.Conflicts.Add("Локальное и действующее правило различаются: " + details); continue; }
            if (rule.Ports != plan.RdpPort.ToString(System.Globalization.CultureInfo.InvariantCulture) || rule.Protocol == 256)
            { plan.Conflicts.Add("Широкое разрешение включает RDP; автоматическое отключение затронет другие службы: " + details); continue; }
            if (!plan.Disable.Any(r => r.Id == persistent.Id)) plan.Disable.Add(persistent);
        }
    }
    private static void ClassifyBlock(FirewallRule rule, FirewallPlan plan, Cidr[] trusted, string details)
    {
        details += $" Удалённые адреса: {rule.Remote}.";
        var addresses = rule.Remote.Split(',', StringSplitOptions.TrimEntries);
        if (addresses.Any(Any))
        {
            plan.Conflicts.Add("Явный запрет затрагивает RDP: " + details);
            return;
        }

        var blocked = ParseRemoteAddresses(rule.Remote);
        if (blocked is null)
        {
            plan.Conflicts.Add("Не удалось определить область действия запрета RDP: " + details);
            return;
        }

        var affected = trusted.Where(t => blocked.Any(b => t.Contains(b.Network) || b.Contains(t.Network)))
            .Select(t => t.Canonical).ToArray();
        if (blocked.Any(b => b.Prefix == 0) || affected.Length != 0)
        {
            var overlap = affected.Length == 0 ? "" : $" Пересечение с белым списком: {string.Join(", ", affected)}.";
            plan.Conflicts.Add("Явный запрет затрагивает RDP: " + details + overlap);
            return;
        }

        plan.Warnings.Add("Существующий запрет сохранится. Указанные адреса могут не получить доступ к RDP после авторизации: " + details);
    }
    private static Cidr[]? ParseRemoteAddresses(string addresses)
    {
        try
        {
            return Cidr.NormalizeFirewallAddresses(addresses).Split(',').Select(Cidr.Parse).ToArray();
        }
        catch (Exception ex) when (ex is FormatException or OverflowException)
        {
            return null;
        }
    }
    private static bool Any(string value) => value.Length == 0 || value == "*" || value.Equals("Any", StringComparison.OrdinalIgnoreCase);
    public enum PortMatch { No, Yes, Unknown }
    public static PortMatch MatchPort(string value, int port)
    {
        if (Any(value)) return PortMatch.Yes;
        if (int.TryParse(value, out int number)) return number == port ? PortMatch.Yes : PortMatch.No;
        var range = value.Split('-');
        if (range.Length == 2 && int.TryParse(range[0], out int from) && int.TryParse(range[1], out int to) && from <= to) return from <= port && port <= to ? PortMatch.Yes : PortMatch.No;
        // These are service-specific Windows port keywords, not arbitrary port ranges.
        if (new[] { "IPHTTPS", "IPHTTPSIn", "IPHTTPSOut", "RPC", "RPCEPMap", "RPC-EPMap", "Teredo", "Ply2Disc" }.Contains(value, StringComparer.OrdinalIgnoreCase)) return PortMatch.No;
        return PortMatch.Unknown;
    }
}

public static class NetSecurityProjection
{
    public static void EnrichLocalConstraints(IEnumerable<FirewallRule> rules)
    {
        // Some Windows versions expose PFN in the local rule store, but not through the
        // older NetSecurity application filter. Read ONLY the exact stable local rule ID.
        using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules");
        foreach (var rule in rules)
        {
            if (!rule.Source.Equals("Local", StringComparison.OrdinalIgnoreCase) || !rule.Id.StartsWith("net:", StringComparison.Ordinal)) continue;
            if (key?.GetValue(rule.Id[4..]) is not string raw) continue;
            var families = raw.Split('|').Where(p => p.StartsWith("PFN=", StringComparison.Ordinal)).ToArray();
            if (families.Length == 1) rule.PackageFamilyName = families[0][4..];
        }
    }
    // Identity is NetSecurity.Name; DisplayName is informational and may repeat by profile/language.
    public const string Script = """
function Initialize-KgFilters([string]$store,[object[]]$rules) {
    $script:kgFilters=@{}
    $commands=@{Port='Get-NetFirewallPortFilter';Address='Get-NetFirewallAddressFilter';Application='Get-NetFirewallApplicationFilter';Service='Get-NetFirewallServiceFilter';Interface='Get-NetFirewallInterfaceFilter';InterfaceType='Get-NetFirewallInterfaceTypeFilter';Security='Get-NetFirewallSecurityFilter'}
    foreach($kind in $commands.Keys){
        $map=@{}; $ambiguous=@{}
        try {$filters=@(& $commands[$kind] -PolicyStore $store -ErrorAction Stop)}
        catch {
            if($null -eq $rules){$rules=@(Get-NetFirewallRule -PolicyStore $store | Where-Object {$_.Enabled -eq 'True' -and $_.Direction -eq 'Inbound'})}
            $filters=@($rules | & $commands[$kind] -ErrorAction Stop)
        }
        foreach($filter in $filters){
            $id=[string]$filter.InstanceID
            if($id -eq '' -or $ambiguous.ContainsKey($id)){continue}
            if($map.ContainsKey($id)){$map.Remove($id);$ambiguous[$id]=$true;continue}
            $map[$id]=$filter
        }
        $script:kgFilters[$kind]=$map
    }
}
function Get-KgFilter($r,[string]$kind){
    if($null -ne $script:kgFilters -and $script:kgFilters.ContainsKey($kind)){
        $map=$script:kgFilters[$kind]
        if($map.ContainsKey([string]$r.Name)){return $map[[string]$r.Name]}
    }
    switch($kind){
        'Port' {$r | Get-NetFirewallPortFilter}
        'Address' {$r | Get-NetFirewallAddressFilter}
        'Application' {$r | Get-NetFirewallApplicationFilter}
        'Service' {$r | Get-NetFirewallServiceFilter}
        'Interface' {$r | Get-NetFirewallInterfaceFilter}
        'InterfaceType' {$r | Get-NetFirewallInterfaceTypeFilter}
        'Security' {$r | Get-NetFirewallSecurityFilter}
    }
}
function Convert-KgRule($r) {
    $p=Get-KgFilter $r 'Port'
    $protocol = switch([string]$p.Protocol){ 'TCP' {6} 'UDP' {17} 'Any' {256} 'ICMPv4' {1} 'ICMPv6' {58} default { $number=0; if([int]::TryParse([string]$p.Protocol,[ref]$number)){$number}else{-1} } }
    if($protocol -notin @(6,17,256)){return}
    $authRule=$false
    if($null -ne $kgPort){
        $relevant=$false
        foreach($portText in @($p.LocalPort)){
            $portText=[string]$portText
            if($portText -in @('Any','*','')){$relevant=$true;break}
            $number=0
            if([int]::TryParse($portText,[ref]$number)){if($number -eq $kgPort){$relevant=$true};continue}
            if($portText -match '^(\d+)-(\d+)$'){if([int]$Matches[1] -le $kgPort -and [int]$Matches[2] -ge $kgPort){$relevant=$true};continue}
            $relevant=$true
        }
        if($null -ne $kgAuthPort -and $protocol -in @(17,256) -and [string]$r.Action -eq 'Block'){
            foreach($portText in @($p.LocalPort)){
                $portText=[string]$portText
                $number=0
                if([int]::TryParse($portText,[ref]$number)){if($number -eq $kgAuthPort){$authRule=$true;break};continue}
                if($portText -match '^(\d+)-(\d+)$'){if([int]$Matches[1] -le $kgAuthPort -and [int]$Matches[2] -ge $kgAuthPort){$authRule=$true;break};continue}
                if($portText -notin @('IPHTTPS','IPHTTPSIn','IPHTTPSOut','RPC','RPCEPMap','RPC-EPMap','Teredo','Ply2Disc')){$authRule=$true;break}
            }
        }
        if(-not $relevant -and -not $authRule){return}
    }
    $app=Get-KgFilter $r 'Application'
    $svc=Get-KgFilter $r 'Service'
    if(-not $authRule -and [string]$svc.Service -notin @('','Any','*','TermService')){return}
    $program=[Environment]::ExpandEnvironmentVariables([string]$app.Program)
    if(-not $authRule -and $program -notin @('','Any','*','System') -and -not $program.EndsWith('\svchost.exe',[StringComparison]::OrdinalIgnoreCase) -and -not $program.EndsWith('\System',[StringComparison]::OrdinalIgnoreCase)){return}
    $a=Get-KgFilter $r 'Address'
    $if=Get-KgFilter $r 'Interface'
    $it=Get-KgFilter $r 'InterfaceType'
    $sec=Get-KgFilter $r 'Security'
    $dynamic=[string]$p.DynamicTarget
    if($dynamic -eq ''){$dynamic=[string]$p.DynamicTransport}
    if($dynamic -eq '' -and $null -ne $p.CimInstanceProperties){
        $rawDynamic=$p.CimInstanceProperties['DynamicTransport']
        if($null -ne $rawDynamic){$dynamic=[string]$rawDynamic.Value}
    }
    $profiles=[int]$r.Profile; if($profiles -eq 0){$profiles=7}
    $scope=[ordered]@{
        LocalAddresses=@($a.LocalAddress | Sort-Object); RemotePorts=@($p.RemotePort | Sort-Object)
        IcmpType=[string]$p.IcmpType; DynamicTarget=$dynamic
        InterfaceAlias=@($if.InterfaceAlias | Sort-Object); InterfaceType=[string]$it.InterfaceType
        EdgeTraversal=[string]$r.EdgeTraversalPolicy; LooseSource=[string]$r.LooseSourceMapping; LocalOnly=[string]$r.LocalOnlyMapping
        Package=[string]$app.Package; Authentication=[string]$sec.Authentication; Encryption=[string]$sec.Encryption
        OverrideBlock=[string]$sec.OverrideBlockRules; LocalUser=[string]$sec.LocalUser; RemoteUser=[string]$sec.RemoteUser; RemoteMachine=[string]$sec.RemoteMachine
    }
    [pscustomobject]@{
        Id=('net:'+[string]$r.Name); Name=[string]$r.DisplayName; Group=[string]$r.Group
        Source=[string]$r.PolicyStoreSourceType; Ports=(@($p.LocalPort | Sort-Object) -join ','); Remote=(@($a.RemoteAddress | Sort-Object) -join ',')
        Application=[string]$app.Program; Service=[string]$svc.Service; Protocol=$protocol
        Direction=$(if([string]$r.Direction -eq 'Inbound'){1}else{2}); Action=$(if([string]$r.Action -eq 'Allow'){1}else{0})
        Profiles=$profiles; Enabled=([string]$r.Enabled -eq 'True'); Scope=($scope | ConvertTo-Json -Depth 5 -Compress)
        Package=[string]$app.Package; DynamicTransport=$dynamic
    }
}
""";
}
