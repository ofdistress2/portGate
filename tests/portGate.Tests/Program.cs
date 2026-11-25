using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using portGate.Core;

int passed = 0;
bool offline = args.Contains("--offline");
string? policySnapshot = args.SingleOrDefault(arg => arg != "--offline");
void Check(bool success, string name) { if (!success) throw new Exception("FAIL: " + name); Console.WriteLine("PASS: " + name); passed++; }
void Reject(Action action, string name) { try { action(); } catch { Check(true, name); return; } throw new Exception("FAIL: " + name); }
string temp = Path.Combine(Path.GetTempPath(), "portGate.Tests." + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(temp);
var store = new Store(temp); store.Initialize(false);
var config = store.Config(); config.RdpPort = 3389; store.SaveConfig(config);
var firewall = new MemoryFirewall(); var engine = new Engine(store, firewall);
var client = engine.CreateClient("Test", 300, null); byte[] key = Native.Unprotect(client.ProtectedKey);
Check(key.Length == 32, "DPAPI round-trip");
Check(Cidr.Parse("10.0.0.0/24").Contains(IPAddress.Parse("::ffff:10.0.0.2")), "IPv4-mapped normalization");
Check(!Cidr.Parse("10.0.0.0/24").Contains(IPAddress.Parse("10.0.1.2")), "CIDR rejects outside network");
Check(Cidr.Parse("2001:db8::/32").Contains(IPAddress.Parse("2001:db8::1")), "IPv6 CIDR");
Reject(() => Cidr.Parse("10.0.0.1/33"), "Invalid CIDR rejected");
Reject(() => new Config { TrustedRdpCidrs = ["0.0.0.0/0"] }.Validate(), "Unrestricted RDP is rejected");
Reject(() => new Config { TrustedRdpCidrs = ["::/1", "8000::/2", "c000::/2"] }.Validate(), "Adjacent prefixes cannot combine into unrestricted RDP");
new Config { TrustedRdpCidrs = ["192.0.2.0/24"], AllowedKnockCidrs = ["0.0.0.0/0", "::/0"] }.Validate();
string signed = Protocol.Pack("KG1|HELLO|test|test|0|abc", key);
Check(Protocol.Verify(signed, key) && !Protocol.Verify(signed.Replace("abc", "abd"), key), "HMAC tamper rejection");
Check(Protocol.Sign("Hi There", Enumerable.Repeat((byte)0x0b, 20).ToArray()) == "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7", "RFC 4231 deterministic HMAC vector");
Check(Cidr.NormalizeFirewallAddresses("10.20.0.0/255.255.255.0,203.0.113.10") == Cidr.NormalizeFirewallAddresses("203.0.113.10/32,10.20.0.7/24"), "Windows firewall address normalization");
Check(Json.Write(new { text = "Русский текст" }).Contains("Русский текст", StringComparison.Ordinal), "JSON diagnostics show readable Russian");
Check(Native.PowerShell("[Console]::Write('Сообщение об ошибке')") == "Сообщение об ошибке", "UTF-8 process output round-trip");
string mockNetSecurity = """
function Get-NetFirewallPortFilter { process { [pscustomobject]@{Protocol='TCP';LocalPort=@('3389');RemotePort=@('Any');IcmpType='Any';DynamicTarget='Any'} } }
function Get-NetFirewallAddressFilter { process { [pscustomobject]@{LocalAddress=@('Any');RemoteAddress=@('Any')} } }
function Get-NetFirewallApplicationFilter { process { [pscustomobject]@{Program='Any';Package=''} } }
function Get-NetFirewallServiceFilter { process { [pscustomobject]@{Service='TermService'} } }
function Get-NetFirewallInterfaceFilter { process { [pscustomobject]@{InterfaceAlias=@('Any')} } }
function Get-NetFirewallInterfaceTypeFilter { process { [pscustomobject]@{InterfaceType='Any'} } }
function Get-NetFirewallSecurityFilter { process { [pscustomobject]@{Authentication='NotRequired';Encryption='NotRequired';OverrideBlockRules=$false;LocalUser='Any';RemoteUser='Any';RemoteMachine='Any'} } }
$r=[pscustomobject]@{Name='RemoteDesktop-UserMode-In-TCP';DisplayName='Удалённый рабочий стол';Group='Remote Desktop';PolicyStoreSourceType='Local';Profile=0;Direction='Inbound';Action='Allow';Enabled='True';EdgeTraversalPolicy='Block';LooseSourceMapping=$false;LocalOnlyMapping=$false}
$kgPort=3389
Convert-KgRule $r | ConvertTo-Json -Depth 10 -Compress
""";
var projected = Json.Read<FirewallRule>(Native.PowerShell(NetSecurityProjection.Script + "\n" + mockNetSecurity));
Check(projected.Id == "net:RemoteDesktop-UserMode-In-TCP" && projected.Name == "Удалённый рабочий стол" && projected.Protocol == 6 && projected.Profiles == 7, "PowerShell 5.1 NetSecurity projection preserves stable ID and Russian display name");
FirewallRule RdpRule(string id, string name, int protocol = 6) => new() { Id = "net:" + id, Name = name, Ports = "3389", Protocol = protocol, Source = "Local" };
var rdp1 = RdpRule("RemoteDesktop-UserMode-In-TCP", "Удалённый рабочий стол");
var rdp2 = RdpRule("RemoteDesktop-UserMode-In-UDP", "Удалённый рабочий стол", 17);
var duplicatePlan = new FirewallPlan { RdpPort = 3389 };
FirewallClassifier.Analyze([rdp1, rdp2], [rdp1, rdp2], duplicatePlan);
Check(duplicatePlan.Safe && duplicatePlan.Disable.Count == 2 && duplicatePlan.Disable[0].Identity != duplicatePlan.Disable[1].Identity, "Duplicate DisplayName uses unique NetSecurity identity");
var localized = RdpRule("RemoteDesktop-UserMode-In-TCP", "Remote Desktop");
Check(localized.Fingerprint == rdp1.Fingerprint, "Localized display name does not change stable rule identity or policy fingerprint");
var iphttps = RdpRule("CoreNet-IPHTTPS-In", "IPHTTPS"); iphttps.Ports = "IPHTTPSIn";
var symbolicPlan = new FirewallPlan { RdpPort = 3389 }; FirewallClassifier.Analyze([iphttps], [iphttps], symbolicPlan);
Check(symbolicPlan.Safe && symbolicPlan.Disable.Count == 0, "IPHTTPS keyword is not an arbitrary RDP port");
var wide = RdpRule("broad", "Any inbound"); wide.Ports = "Any";
var broadPlan = new FirewallPlan { RdpPort = 3389 }; FirewallClassifier.Analyze([wide], [wide], broadPlan);
Check(!broadPlan.Safe && broadPlan.Disable.Count == 0 && broadPlan.Conflicts[0].Contains("Any inbound"), "Real broad allow remains a descriptive conflict");
var packaged = RdpRule("packaged", "Packaged application"); packaged.Ports = "Any"; packaged.PackageFamilyName = "Microsoft.Windows.CloudExperienceHost_cw5n1h2txyewy";
var packagePlan = new FirewallPlan { RdpPort = 3389 }; FirewallClassifier.Analyze([packaged], [packaged], packagePlan);
Check(packagePlan.Safe && packagePlan.Disable.Count == 0, "Package-family restricted permit does not allow TermService");
var dynamicRule = RdpRule("wifi-driver", "Wi-Fi driver"); dynamicRule.Ports = "Any"; dynamicRule.DynamicTransport = "32";
var dynamicPlan = new FirewallPlan { RdpPort = 3389 }; FirewallClassifier.Analyze([dynamicRule], [dynamicRule], dynamicPlan);
Check(dynamicPlan.Safe && dynamicPlan.Disable.Count == 0, "Special Wi-Fi dynamic transport is not a general RDP permit");
dynamicRule.DynamicTransport = "1024";
var futureDynamicPlan = new FirewallPlan { RdpPort = 3389 }; FirewallClassifier.Analyze([dynamicRule], [dynamicRule], futureDynamicPlan);
Check(!futureDynamicPlan.Safe, "Unknown dynamic transport is not silently ignored");
var unknown = RdpRule("unknown", "Dynamic unknown"); unknown.Ports = "FutureKeyword";
var unknownPlan = new FirewallPlan { RdpPort = 3389 }; FirewallClassifier.Analyze([unknown], [unknown], unknownPlan);
Check(!unknownPlan.Safe, "Unknown port keyword is not silently ignored");
var duplicateIdPlan = new FirewallPlan { RdpPort = 3389 }; FirewallClassifier.Analyze([rdp1], [rdp1, rdp1], duplicateIdPlan);
Check(!duplicateIdPlan.Safe, "Duplicate stable identity still rejected");
var domain = RdpRule("domain", "Domain rule"); domain.Source = "GroupPolicy";
var domainPlan = new FirewallPlan { RdpPort = 3389 }; FirewallClassifier.Analyze([domain], [], domainPlan);
Check(!domainPlan.Safe && domainPlan.Disable.Count == 0, "Domain rule is never disabled locally");
var block = RdpRule("block", "Block rule"); block.Action = 0;
var blockPlan = new FirewallPlan { RdpPort = 3389 }; FirewallClassifier.Analyze([block], [block], blockPlan);
Check(!blockPlan.Safe && blockPlan.Conflicts[0].Contains("Явный запрет"), "Block rule has a distinct explanation");
var customAllow = RdpRule("custom", "Custom fixed-address rule"); customAllow.Remote = "203.0.113.10,2001:db8:10::/64";
var cyberarms = RdpRule("ids", "IDS block"); cyberarms.Action = 0; cyberarms.Ports = "Any"; cyberarms.Protocol = 256; cyberarms.Remote = "198.51.100.42";
var scopedPlan = new FirewallPlan { RdpPort = 3389 };
FirewallClassifier.Analyze([rdp1, customAllow, cyberarms], [rdp1, customAllow, cyberarms], scopedPlan, ["203.0.113.10/32"]);
Check(scopedPlan.Safe && scopedPlan.Disable.Select(r => r.Id).SequenceEqual([rdp1.Id]) && scopedPlan.Warnings.Count == 2, "Only the unrestricted RDP permit is disabled; fixed-source permit and IDS block are preserved");
var overlapPlan = new FirewallPlan { RdpPort = 3389 };
FirewallClassifier.Analyze([cyberarms], [cyberarms], overlapPlan, ["198.51.100.0/24"]);
Check(!overlapPlan.Safe && overlapPlan.Disable.Count == 0 && overlapPlan.Conflicts[0].Contains("198.51.100.0/24"), "An IDS block overlapping the trusted list remains a conflict");
var authBlock = new FirewallRule { Name = "Block authorization", Ports = "51888", Protocol = 17, Action = 0 };
var authPlan = new FirewallPlan { RdpPort = 3389 };
FirewallClassifier.AnalyzeAuthorization([authBlock], config, authPlan);
Check(!authPlan.Safe && authPlan.Conflicts[0].Contains("51888"), "Explicit UDP authorization block is classified even on a non-RDP port");
authBlock.Remote = "198.51.100.42";
authPlan = new FirewallPlan { RdpPort = 3389 };
FirewallClassifier.AnalyzeAuthorization([authBlock], config, authPlan);
Check(authPlan.Safe && authPlan.Warnings.Count == 1, "Scoped UDP ban remains a warning");
customAllow.Remote = "0.0.0.0/0";
var allSourcesPlan = new FirewallPlan { RdpPort = 3389 };
FirewallClassifier.Analyze([customAllow], [customAllow], allSourcesPlan);
Check(allSourcesPlan.Safe && allSourcesPlan.Disable.Count == 1, "Zero-prefix permit is unrestricted");
var sourceDirectory = Path.Combine(temp, "package"); var targetDirectory = Path.Combine(temp, "installed");
Directory.CreateDirectory(Path.Combine(sourceDirectory, "Templates"));
File.WriteAllText(Path.Combine(sourceDirectory, Deployment.PackagedHostName), "test executable placeholder");
File.WriteAllText(Path.Combine(sourceDirectory, "Templates", "knock.ps1"), "test template");
File.WriteAllText(Path.Combine(sourceDirectory, "package-manifest.json"), Json.Write(new[] { Deployment.PackagedHostName, "Templates/knock.ps1" }));
File.WriteAllText(Path.Combine(sourceDirectory, "unrelated-desktop-document.txt"), "must not be copied");
string legacyHostPath = Path.Combine(targetDirectory, Deployment.InstalledHostName);
Directory.CreateDirectory(targetDirectory);
File.WriteAllText(legacyHostPath, "pilot executable");
using (var stagedUpdate = Deployment.StagePackage(sourceDirectory, targetDirectory))
{
    string updatedHost = stagedUpdate.Activate();
    Check(updatedHost == legacyHostPath && File.ReadAllText(updatedHost) == "test executable placeholder",
        "Update keeps the pilot service and task executable path");
    stagedUpdate.Rollback();
    Check(File.ReadAllText(legacyHostPath) == "pilot executable", "Failed upgrade restores the pilot executable");
}
string installedPath = Deployment.CopyPackage(sourceDirectory, targetDirectory);
var installedManifest = Json.Read<string[]>(File.ReadAllText(Path.Combine(targetDirectory, "package-manifest.json")));
Check(installedManifest.Contains(Deployment.InstalledHostName) && !installedManifest.Contains(Deployment.PackagedHostName),
    "Installed manifest lists the actual executable filename");
Check(File.Exists(installedPath) && File.Exists(Path.Combine(targetDirectory, "Templates", "knock.ps1")), "Installer copies complete package without service registration");
Check(!File.Exists(Path.Combine(targetDirectory, "unrelated-desktop-document.txt")), "Installer does not copy unrelated desktop files");
Check(Deployment.CopyPackage(targetDirectory, targetDirectory) == installedPath, "Installation from installed folder is idempotent");
using (var busyFile = new FileStream(installedPath, FileMode.Open, FileAccess.Read, FileShare.None))
    Reject(() => Deployment.CopyPackage(sourceDirectory, targetDirectory), "Installer rejects locked files before replacing the installed package");
Reject(() => Deployment.CopyPackage(sourceDirectory, Path.Combine(sourceDirectory, "nested")), "Installer rejects nested source and target");
var initial = store.Load(); initial.Migration = new Migration { Confirmed = true, Config = config }; store.Save(initial);
DateTimeOffset now = DateTimeOffset.UtcNow; var ip = IPAddress.Parse("198.51.100.5");
string nonce = Protocol.RandomHex();
string hello = Protocol.Pack($"KG1|HELLO|{config.ServerId}|{client.Id}|{now.ToUnixTimeSeconds()}|{nonce}", key);
string challenge = engine.Handle(hello, ip, now) ?? throw new Exception("No challenge");
Check(Protocol.Verify(challenge, key), "Challenge signature");
Check(challenge == engine.Handle(hello, ip, now), "HELLO retry idempotent");
var fields = challenge.Split('|');
string proof = Protocol.Pack($"KG1|PROOF|{config.ServerId}|{client.Id}|{nonce}|{fields[5]}|{fields[6]}", key);
Check(engine.Handle(proof, IPAddress.Parse("198.51.100.6"), now) == null, "Challenge bound to IP");
string result = engine.Handle(proof, ip, now) ?? throw new Exception("No result");
Check(Protocol.Verify(result, key) && firewall.Rules().Count == 2, "Valid proof installs exact TCP and UDP permits");
Check(engine.Handle(proof, ip, now) == result && store.Load().Leases.Count == 1, "PROOF retry does not extend lease");
Check(engine.Handle(hello.Replace(config.ServerId, "wrongserver"), ip, now) == null, "Wrong server rejected");
foreach (long stamp in new[] { 0L, now.AddMinutes(-3).ToUnixTimeSeconds(), now.AddMinutes(3).ToUnixTimeSeconds() })
{
    var freshNonce = Protocol.RandomHex();
    var helloWithSkew = Protocol.Pack($"KG1|HELLO|{config.ServerId}|{client.Id}|{stamp}|{freshNonce}", key);
    var response = engine.Handle(helloWithSkew, ip, now)?.Split('|') ?? throw new Exception("Clock-independent HELLO was rejected");
    var signedProof = Protocol.Pack($"KG1|PROOF|{config.ServerId}|{client.Id}|{freshNonce}|{response[5]}|{response[6]}", key);
    Check(engine.Handle(signedProof, ip, now) is { } signedResult && Protocol.Verify(signedResult, key), $"Clock-independent authorization with HELLO field {stamp}");
}
var replayNonce = Protocol.RandomHex();
var replayHello = Protocol.Pack($"KG1|HELLO|{config.ServerId}|{client.Id}|0|{replayNonce}", key);
var firstChallenge = engine.Handle(replayHello, ip, now)!.Split('|');
var replayProof = Protocol.Pack($"KG1|PROOF|{config.ServerId}|{client.Id}|{replayNonce}|{firstChallenge[5]}|{firstChallenge[6]}", key);
Check(engine.Handle(replayProof, ip, now.AddSeconds(config.ChallengeSeconds + 1)) == null, "Server rejects a proof after its challenge expires");
var afterRetention = now.AddSeconds(config.ChallengeSeconds + 61);
var newChallenge = engine.Handle(replayHello, ip, afterRetention)!.Split('|');
Check(newChallenge[5] != firstChallenge[5] && engine.Handle(replayProof, ip, afterRetention) == null, "A replayed HELLO after retention receives a new challenge and cannot reuse the old proof");
Check(engine.Handle(new string('x', 1201), ip, now) == null, "Oversized packet rejected");
var rateCheck = new Engine(store, firewall);
for (int i = 0; i < 250; i++) rateCheck.Handle("KG1|incomplete", ip, now);
var otherIp = IPAddress.Parse("198.51.100.7");
string secondNonce = Protocol.RandomHex();
string secondHello = Protocol.Pack($"KG1|HELLO|{config.ServerId}|{client.Id}|0|{secondNonce}", key);
var secondChallenge = rateCheck.Handle(secondHello, otherIp, now)?.Split('|');
Check(secondChallenge != null, "Traffic from one source leaves capacity for another");
string secondProof = Protocol.Pack($"KG1|PROOF|{config.ServerId}|{client.Id}|{secondNonce}|{secondChallenge![5]}|{secondChallenge[6]}", key);
Check(rateCheck.Handle(secondProof, otherIp, now) != null, "A second address can independently obtain a lease");
string revokeId = store.Load().Leases.Single(l => l.Ip == ip.ToString()).RuleId;
rateCheck.RevokeLease(revokeId);
Check(store.Load().Clients.Single().Enabled && store.Load().Leases.Single().Ip == otherIp.ToString() &&
    firewall.Rules().Count == 2 && rateCheck.Handle(proof, ip, now) == null,
    "Targeted revocation removes only the selected lease and invalidates its cached proof");
engine.ChangeClient(client.Id, false);
Check(firewall.Rules().Count == 0 && engine.Handle(proof, ip, now) == null, "Revocation removes rules and rejects replay");
engine.ChangeClient(client.Id, true);
Check(engine.Handle(hello, ip, now) == null, "Rotation rejects old key");
var newer = store.Load().Clients.Single(); key = Native.Unprotect(newer.ProtectedKey);
string h2 = Protocol.Pack($"KG1|HELLO|{config.ServerId}|{client.Id}|{now.ToUnixTimeSeconds()}|{Protocol.RandomHex()}", key);
var f2 = engine.Handle(h2, ip, now)!.Split('|');
string p2 = Protocol.Pack($"KG1|PROOF|{config.ServerId}|{client.Id}|{f2[4]}|{f2[5]}|{f2[6]}", key);
_ = engine.Handle(p2, ip, now);
engine.Startup();
Check(firewall.Rules().Count == 0 && engine.Handle(p2, ip, now) == null && engine.Handle(h2, ip, now) == null, "Restart clears permits without reopening captured requests");
var prepared = store.Load(); var orphan = new Lease { ClientId = client.Id, Ip = ip.ToString(), RuleId = "KG.Lease.orphan", Expires = now.AddMinutes(5) }; prepared.Leases.Add(orphan); store.Save(prepared);
firewall.Put(new() { Name = orphan.RuleId + ".tcp", Group = WindowsFirewall.Group }); engine.Cleanup();
Check(firewall.Rules().Count == 0, "Incomplete grant removed by cleanup");
var expired = store.Load(); expired.Leases.Add(new() { ClientId = client.Id, Ip = ip.ToString(), RuleId = "KG.Lease.expired", Expires = now.AddSeconds(-1), Phase = "Committed" }); store.Save(expired);
firewall.Put(new() { Name = "KG.Lease.expired.tcp", Group = WindowsFirewall.Group }); engine.Cleanup();
Check(firewall.Rules().Count == 0, "Expired lease removed");
// Live loopback exchange with the generated PowerShell 5.1 script, in-memory firewall only.
string templatePath = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "Templates", "knock.ps1"));
Directory.CreateDirectory(Path.GetDirectoryName(templatePath)!);
string sourceTemplate = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../../src/portGate.Host/Templates/knock.ps1"));
File.Copy(sourceTemplate, templatePath, true);
using var udp = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
config.UdpPort = ((IPEndPoint)udp.Client.LocalEndPoint!).Port; store.SaveConfig(config);
string script = ScriptExporter.Export(store, client.Id, "127.0.0.1", false, "ps1");
string exportDirectory = Path.Combine(temp, "Рабочий стол"); Directory.CreateDirectory(exportDirectory);
string scriptPath = Path.Combine(exportDirectory, "Мой доступ.ps1"); Store.Atomic(scriptPath, script, false, true);
Check(File.Exists(scriptPath) && Directory.GetFiles(exportDirectory).Length == 1, "Offline export creates one file in a path with spaces and Cyrillic");
Check(File.ReadAllBytes(scriptPath).Take(3).SequenceEqual(new byte[] {0xef,0xbb,0xbf}), "Export has UTF-8 BOM for PowerShell 5.1");
Check(script.Contains("KG1|HELLO|$serverId|$clientId|0|$nonce") && !script.Contains("::UtcNow"),
    "Windows clients do not use their wall clock for authorization");
string macScript = ScriptExporter.Export(store, client.Id, "127.0.0.1", false, "applescript");
string programLine = macScript.Split('\n').Single(line => line.TrimStart().StartsWith("set clientProgram to ", StringComparison.Ordinal));
string perlProgram = Json.Read<string>(programLine.TrimStart()["set clientProgram to ".Length..]);
Check(macScript.Contains("use framework \"Foundation\"") && macScript.Contains("setArguments:{\"-\"}") &&
    macScript.Contains("setStandardInput:inputPipe") && !perlProgram.Contains("@@") &&
    perlProgram.Contains("my $server = '127.0.0.1';") && perlProgram.Contains("my $port = " + config.UdpPort + ";") &&
    perlProgram.Contains(client.Id), "macOS export contains a personalized UDP client passed to Perl through stdin");
Check(macScript.Contains("Доступ открыт до") && macScript.Contains("Доступ RDP не подтверждён") &&
    macScript.Contains("Не получено подписанное подтверждение") && !macScript.Contains("do shell script"),
    "macOS export distinguishes success and failure without invoking a shell");
Check(macScript.Contains("child's |launch|()") && !macScript.Contains("child's launch()"),
    "macOS export escapes the NSTask launch selector to avoid Apple's launch command");
Check(perlProgram.Contains("$server_id, $client_id, 0, $nonce") && !perlProgram.Contains("time()"),
    "macOS client does not use its wall clock for authorization");
if (Environment.GetEnvironmentVariable("PORTGATE_TEST_PERL") is { Length: > 0 } perlPath)
{
    using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(35));
    var start = new System.Diagnostics.ProcessStartInfo(perlPath)
    {
        UseShellExecute = false, CreateNoWindow = true,
        RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true,
        StandardInputEncoding = new UTF8Encoding(false)
    };
    start.ArgumentList.Add("-");
    using var process = System.Diagnostics.Process.Start(start)!;
    try
    {
        var stdout = process.StandardOutput.ReadToEndAsync(deadline.Token);
        var stderr = process.StandardError.ReadToEndAsync(deadline.Token);
        await process.StandardInput.WriteAsync(perlProgram.AsMemory(), deadline.Token);
        process.StandardInput.Close();
        for (int i = 0; i < 2; i++)
        {
            var packet = await udp.ReceiveAsync(deadline.Token);
            string? reply = engine.Handle(Encoding.UTF8.GetString(packet.Buffer), packet.RemoteEndPoint.Address, DateTimeOffset.UtcNow.AddMinutes(-3));
            if (reply == null) throw new Exception("Embedded macOS client failed protocol validation");
            if (i == 0)
            {
                string invalidReply = reply[..^1] + (reply[^1] == '0' ? '1' : '0');
                await udp.SendAsync(Encoding.UTF8.GetBytes(invalidReply), packet.RemoteEndPoint, deadline.Token);
            }
            await udp.SendAsync(Encoding.UTF8.GetBytes(reply), packet.RemoteEndPoint, deadline.Token);
        }
        await process.WaitForExitAsync(deadline.Token);
        string output = await stdout;
        Check(process.ExitCode == 0 && output.StartsWith("KG_OK|") && output.TrimEnd().EndsWith("|127.0.0.1|3389") &&
            string.IsNullOrEmpty(await stderr), "Embedded Perl client rejects an invalid MAC and completes the UDP exchange with a three-minute clock difference");
        engine.RevokeAll();
    }
    finally { if (!process.HasExited) process.Kill(true); }
}
else Console.WriteLine("SKIP: Launch embedded Perl UDP client (set PORTGATE_TEST_PERL).");
if (!offline)
{
    using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
    var responder = Task.Run(async () =>
    {
        for (int i = 0; i < 2; i++)
        {
            var packet = await udp.ReceiveAsync(timeout.Token);
            var reply = engine.Handle(Encoding.UTF8.GetString(packet.Buffer), packet.RemoteEndPoint.Address, DateTimeOffset.UtcNow);
            if (reply == null) throw new Exception("Rejected generated script");
            await udp.SendAsync(Encoding.UTF8.GetBytes(reply), packet.RemoteEndPoint, timeout.Token);
        }
    });
    string output = Native.Run("powershell.exe", ["-NoProfile", "-NonInteractive", "-File", scriptPath, "-NoRdp"], 15000);
    await responder;
    Check(output.Contains("RDP") && store.Load().Leases.Count == 1, "Generated script completes live UDP exchange in Windows PowerShell 5.1");
    // Hybrid BAT reads its embedded UTF-8 payload in memory; no temporary PowerShell file.
    string batch = ScriptExporter.Export(store, client.Id, "127.0.0.1", false);
    string batchPath = Path.Combine(exportDirectory, "Мой доступ & 100% ! (тест).bat");
    Store.Atomic(batchPath, batch, false);
    Check(batch.StartsWith("@echo off\r\n") && !batch.Contains("ExecutionPolicy Bypass") && !batch.Contains("-EncodedCommand"), "BAT is ASCII bootstrap without policy bypass");
    string embedded = Encoding.UTF8.GetString(Convert.FromBase64String(batch[(batch.LastIndexOf("::KG_PAYLOAD_BASE64:", StringComparison.Ordinal) + "::KG_PAYLOAD_BASE64:".Length)..].Trim()));
    Check(embedded == script && batch.All(c => c < 128), "BAT embeds the exact UTF-8 script and key in a non-executable payload");
    Reject(() => ScriptExporter.Export(store, client.Id, "127.0.0.1&calc", false), "Export rejects server command injection");
    Reject(() => ScriptExporter.Export(store, client.Id, "127.0.0.1", false, "cmd"), "Export rejects unknown format");
    async Task<(int Code, string Text)> RunBatch(string path)
    {
        var info = new System.Diagnostics.ProcessStartInfo("cmd.exe", "/d /c \"\"" + path + "\"\"") { UseShellExecute = false, RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true };
        using var process = System.Diagnostics.Process.Start(info)!;
        var stdout = process.StandardOutput.ReadToEndAsync(); var stderr = process.StandardError.ReadToEndAsync();
        await process.StandardInput.WriteLineAsync(); process.StandardInput.Close();
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        try { await process.WaitForExitAsync(deadline.Token); } catch { process.Kill(true); throw; }
        return (process.ExitCode, await stdout + await stderr);
    }
    using var batchTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
    var batchResponder = Task.Run(async () => {
        for (int i = 0; i < 2; i++) {
            var packet = await udp.ReceiveAsync(batchTimeout.Token);
            var reply = engine.Handle(Encoding.UTF8.GetString(packet.Buffer), packet.RemoteEndPoint.Address, DateTimeOffset.UtcNow);
            if (reply == null) throw new Exception("Rejected BAT client");
            await udp.SendAsync(Encoding.UTF8.GetBytes(reply), packet.RemoteEndPoint, batchTimeout.Token);
        }
    });
    var batchResult = await RunBatch(batchPath); if (batchResult.Code != 0) { batchTimeout.Cancel(); throw new Exception("BAT bootstrap failed: " + System.Text.RegularExpressions.Regex.Replace(batchResult.Text, "[A-Za-z0-9+/=]{40,}", "[REDACTED]")); } await batchResponder;
    Check(batchResult.Code == 0 && batchResult.Text.Contains("[3/4]") && batchResult.Text.Contains("[4/4]"), "BAT authorizes through actual Windows PowerShell in Unicode/metacharacter path");
    string missingPath = Path.Combine(exportDirectory, "missing.bat");
    Store.Atomic(missingPath, batch.Replace("%SystemRoot%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "%SystemRoot%\\portGate-does-not-exist.exe"), false);
    var missingResult = await RunBatch(missingPath);
    Check(missingResult.Code == 2 && missingResult.Text.Contains("Press any key") && missingResult.Text.Contains("not found"), "Missing PowerShell pauses and returns nonzero");
    // No listener exists at this freshly released loopback endpoint.
    int unusedPort; using (var unused = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0))) unusedPort = ((IPEndPoint)unused.Client.LocalEndPoint!).Port;
    var timeoutConfig = store.Config(); timeoutConfig.UdpPort = unusedPort; store.SaveConfig(timeoutConfig);
    string failurePath = Path.Combine(exportDirectory, "failure.bat"); Store.Atomic(failurePath, ScriptExporter.Export(store, client.Id, "127.0.0.1", false), false);
    var failureResult = await RunBatch(failurePath);
    if (failureResult.Code == 0 || !failureResult.Text.Contains("Press any key") || failureResult.Text.Contains("[3/4]")) throw new Exception("Failure code="+failureResult.Code+" output="+System.Text.RegularExpressions.Regex.Replace(failureResult.Text, "[A-Za-z0-9+/=]{40,}", "[REDACTED]"));
    Check(failureResult.Code != 0 && failureResult.Text.Contains("Press any key") && !failureResult.Text.Contains("[3/4]"), "Network failure cannot report authorization success and keeps error window open");
    Check(!failureResult.Text.Contains("$key =") && !failureResult.Text.Contains(Convert.ToBase64String(key)), "Errors never print embedded source or key");
    using var silentUdp = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
    timeoutConfig.UdpPort = ((IPEndPoint)silentUdp.Client.LocalEndPoint!).Port; store.SaveConfig(timeoutConfig);
    Store.Atomic(failurePath, ScriptExporter.Export(store, client.Id, "127.0.0.1", false), false);
    var timedOut = await RunBatch(failurePath);
    Check(timedOut.Code != 0 && timedOut.Text.Contains("Press any key") && !timedOut.Text.Contains("[3/4]"), "Silent UDP server times out without reporting success");
    using var tamperUdp = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
    timeoutConfig.UdpPort = ((IPEndPoint)tamperUdp.Client.LocalEndPoint!).Port; store.SaveConfig(timeoutConfig);
    Store.Atomic(failurePath, ScriptExporter.Export(store, client.Id, "127.0.0.1", false), false);
    using var tamperDeadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
    var tamperResponder = Task.Run(async () => {
        for (int i = 0; i < 3; i++) {
            var packet = await tamperUdp.ReceiveAsync(tamperDeadline.Token);
            var fields = Encoding.UTF8.GetString(packet.Buffer).Split('|');
            string fake = Protocol.Pack($"KG1|CHALLENGE|{fields[2]}|{fields[3]}|{fields[5]}|{new string('a',32)}|{DateTimeOffset.UtcNow.AddSeconds(30).ToUnixTimeSeconds()}|127.0.0.1", new byte[32]);
            await tamperUdp.SendAsync(Encoding.UTF8.GetBytes(fake), packet.RemoteEndPoint, tamperDeadline.Token);
        }
    });
    var tampered = await RunBatch(failurePath); await tamperResponder;
    Check(tampered.Code != 0 && !tampered.Text.Contains("[3/4]"), "BAT rejects server response with incorrect signature");
    string policyPath = Path.Combine(exportDirectory, "policy.bat");
    Store.Atomic(policyPath, batch.Replace("$p=Get-ExecutionPolicy;", "$p='Restricted';"), false);
    var policyResult = await RunBatch(policyPath);
    Check(policyResult.Code != 0 && policyResult.Text.Contains("Execution policy Restricted") && policyResult.Text.Contains("Press any key"), "Restricted policy branch fails clearly without changing machine policy");
}
else
{
    string batch = ScriptExporter.Export(store, client.Id, "127.0.0.1", false);
    Check(batch.Contains("Review the error above.") && !batch.Contains("PowerShell may be blocked"), "BAT failure footer does not misdiagnose authorization");
    Check(script.Contains("первый ответ сервера") && script.Contains("подтверждение разрешения RDP"), "Exported timeout reports the failed exchange stage");
    Console.WriteLine("SKIP: End-to-end execution of exported BAT/PS1 (--offline).");
}
store.SaveConfig(config);
var broken = File.ReadAllText(store.StatePath).Replace("sha256", "brokenHash"); File.WriteAllText(store.StatePath, broken);
Reject(() => engine.Cleanup(), "Corrupt state fails closed");
Check(firewall.Rules().Count == 0, "Corrupt state removes own temporary permits");
// A separate isolated store tests the migration journal and rollback ordering.
var migrationStore = new Store(Path.Combine(temp, "migration")); migrationStore.Initialize(false);
var mc = migrationStore.Config(); mc.RdpPort = 3389; mc.TrustedRdpCidrs = ["203.0.113.10/32"]; migrationStore.SaveConfig(mc);
var mf = new MemoryFirewall(); var me = new Engine(migrationStore, mf);
mf.Put(new() { Name = "OriginalRdp", Ports = "3389", Protocol = 6 });
var scheduled = new List<DateTimeOffset>();
var confirmationDeadline = me.Apply(scheduled.Add, 12);
Check(scheduled.Count == 2 && scheduled[0] > scheduled[1] && scheduled[1] == confirmationDeadline &&
    migrationStore.Load().Migration!.RollbackAt == confirmationDeadline && confirmationDeadline > DateTimeOffset.UtcNow.AddSeconds(110) &&
    mf.Rules().Any(r => r.Name == "KG.Trusted.6") && !mf.Rules().Single(r => r.Name == "OriginalRdp").Enabled, "Emergency rollback and full confirmation window have explicit deadlines");
Reject(() => me.Confirm(12), "Old RDP session cannot confirm migration");
var ms = migrationStore.Load(); ms.Migration!.RollbackAt = DateTimeOffset.UtcNow.AddSeconds(-1); migrationStore.Save(ms); me.Cleanup();
Check(migrationStore.Load().Migration == null && mf.Rules().Single(r => r.Name == "OriginalRdp").Enabled && mf.Rules().Count == 1, "Unconfirmed generation rolls back to original rules");
mf.Put(new() { Name = "SecondRdp", Ports = "3389", Protocol = 17 });
me.Apply(() => { }, 12);
mf.Rules().Single(r => r.Name == "OriginalRdp").Remote = "192.0.2.9";
Reject(me.Restore, "Rollback refuses to overwrite administrator changes");
Check(mf.Rules().Any(r => r.Name == "KG.Trusted.6"), "Conflicting restore retains trusted access");
Check(mf.Rules().Single(r => r.Name == "SecondRdp").Enabled && migrationStore.Load().Migration!.DisabledRules.Single().Name == "OriginalRdp", "Partial restore restores independent rules and retains only unresolved work");
var duplicateStore = new Store(Path.Combine(temp, "duplicate-names")); duplicateStore.Initialize(false);
var duplicateConfig = duplicateStore.Config(); duplicateConfig.RdpPort = 3389; duplicateConfig.TrustedRdpCidrs = ["203.0.113.10/32"]; duplicateStore.SaveConfig(duplicateConfig);
var duplicateFirewall = new MemoryFirewall(); duplicateFirewall.Put(rdp1); duplicateFirewall.Put(rdp2);
var duplicateEngine = new Engine(duplicateStore, duplicateFirewall);
duplicateEngine.Apply(() => { }, 12);
Check(!duplicateFirewall.Rules().Single(r => r.Id == rdp1.Id).Enabled && !duplicateFirewall.Rules().Single(r => r.Id == rdp2.Id).Enabled, "Migration disables duplicate display names by unique identity");
duplicateEngine.Restore();
Check(duplicateFirewall.Rules().Count == 2 && duplicateFirewall.Rules().All(r => r.Enabled), "Restore recovers each uniquely identified rule");
if (!offline)
{
    string mutexName = "Global\\portGate-Test-" + Guid.NewGuid().ToString("N");
    using var one = Native.SecureMutex(mutexName);
    using var two = Native.SecureMutex(mutexName);
    Check(one.WaitOne(1000) && two.WaitOne(1000), "Secure mutex supports same-thread recursive synchronization");
    two.ReleaseMutex();
    one.ReleaseMutex();
}
else Console.WriteLine("SKIP: Reopening secured global mutex (--offline).");
if (policySnapshot != null)
{
    var realSnapshot = Json.Read<PolicySnapshot>(File.ReadAllText(policySnapshot));
    NetSecurityProjection.EnrichLocalConstraints(realSnapshot.Active.Concat(realSnapshot.Local));
    var realPlan = new FirewallPlan { RdpPort = 3389 };
    FirewallClassifier.Analyze(realSnapshot.Active, realSnapshot.Local, realPlan);
    foreach (string id in new[] { "net:RemoteDesktop-UserMode-In-TCP", "net:RemoteDesktop-UserMode-In-UDP" })
        Check(realPlan.Disable.Any(r => r.Id == id), "Read-only real Windows rule classified by unique ID: " + id);
    Console.WriteLine($"Read-only snapshot: {realSnapshot.Active.Count} candidates, {realPlan.Disable.Count} exact rules, {realPlan.Conflicts.Count} remaining conflicts. No rules changed.");
}
// Exercise the stdout boundary used by Manager, including Console.WriteLine's newline.
var dailyStore = new Store(Path.Combine(temp, "daily")); dailyStore.Initialize(false);
var dailyConfig = dailyStore.Config(); dailyConfig.ServerAddress = "rdp.example.com"; dailyConfig.LeaseSeconds = 86400; dailyConfig.RdpPort = 3389;
dailyStore.SaveConfig(dailyConfig);
var dailyFirewall = new MemoryFirewall(); var dailyEngine = new Engine(dailyStore, dailyFirewall);
var dailyAdmin = new portGate.Host.Administration(dailyEngine, "unused-in-tests.exe");
string createdId = dailyAdmin.Dispatch("clients-create", ["Daily", "86400", ""], 0);
string printedId = Native.PowerShell("[Console]::WriteLine('" + createdId + "')");
Check(printedId != createdId && AccessExport.ParseClientId(printedId) == createdId, "Manager accepts client ID with stdout CRLF");
string dailyScript = ScriptExporter.Export(dailyStore, printedId, "", false, "ps1");
Check(dailyScript.Contains("$server = 'rdp.example.com'") && !dailyScript.Contains("@@"), "Saved server address is used for export without a separate profile");
string dailyPath = Path.Combine(exportDirectory, "Daily.ps1"); Store.Atomic(dailyPath, dailyScript, false, true);
Check(File.Exists(dailyPath), "Creation ID through process stdout exports a real script file");
dailyEngine.ChangeClient(createdId, false);
try { ScriptExporter.Export(dailyStore, createdId, "", false); throw new Exception("Disabled client exported"); }
catch (InvalidOperationException e) { Check(e.Message.Contains("отозван"), "Revoked export reports a meaningful error"); }
dailyEngine.ChangeClient(createdId, true);
var dailyState = dailyStore.Load(); dailyState.Migration = new Migration { Confirmed = true, Config = dailyConfig }; dailyStore.Save(dailyState);
// Address and durations remain editable while policy is active; networking does not.
var updatedDailyConfig = dailyStore.Config(); updatedDailyConfig.ServerAddress = "192.0.2.5"; updatedDailyConfig.MaxLeaseSeconds = 172800;
dailyAdmin.Dispatch("config-save", [Json.Write(updatedDailyConfig)], 0);
Check(dailyStore.Config().ServerAddress == "192.0.2.5", "Server address can be saved without restoring active policy");
updatedDailyConfig.UdpPort++;
Reject(() => dailyAdmin.Dispatch("config-save", [Json.Write(updatedDailyConfig)], 0), "Live firewall/network configuration change is still rejected");
dailyAdmin.Dispatch("clients-edit", [createdId, "Daily updated", "", "86400"], 0);
Check(dailyStore.Load().Clients.Single().LeaseSeconds == 86400, "Existing client's access window can be edited in hours via seconds storage");
byte[] dailyKey = Native.Unprotect(dailyStore.Load().Clients.Single().ProtectedKey);
var grantTime = DateTimeOffset.UtcNow;
string dailyNonce = Protocol.RandomHex();
var dailyChallenge = dailyEngine.Handle(Protocol.Pack($"KG1|HELLO|{dailyConfig.ServerId}|{createdId}|{grantTime.ToUnixTimeSeconds()}|{dailyNonce}", dailyKey), ip, grantTime)!.Split('|');
string dailyProof = Protocol.Pack($"KG1|PROOF|{dailyConfig.ServerId}|{createdId}|{dailyNonce}|{dailyChallenge[5]}|{dailyChallenge[6]}", dailyKey);
string dailyResult = dailyEngine.Handle(dailyProof, ip, grantTime)!;
Check(Protocol.Verify(dailyResult, dailyKey) && dailyStore.Load().Leases.Single().Expires == grantTime.AddHours(24), "Daily authorization grants exactly 24 hours");
dailyEngine.Cleanup();
Check(dailyFirewall.Rules().Count == 2, "Disconnect-independent daily permit survives cleanup while valid");
Check(dailyEngine.Handle(dailyProof, ip, grantTime.AddHours(12)) == null && dailyStore.Load().Leases.Single().Expires == grantTime.AddHours(24), "Expired proof cannot reset the existing 24-hour expiry");
var refreshTime = grantTime.AddSeconds(2);
string refreshNonce = Protocol.RandomHex();
var refreshChallenge = dailyEngine.Handle(Protocol.Pack($"KG1|HELLO|{dailyConfig.ServerId}|{createdId}|{refreshTime.ToUnixTimeSeconds()}|{refreshNonce}", dailyKey), ip, refreshTime)!.Split('|');
var refreshResult = dailyEngine.Handle(Protocol.Pack($"KG1|PROOF|{dailyConfig.ServerId}|{createdId}|{refreshNonce}|{refreshChallenge[5]}|{refreshChallenge[6]}", dailyKey), ip, refreshTime)!;
Check(Protocol.Verify(refreshResult, dailyKey) && dailyStore.Load().Leases.Single().Expires == refreshTime.AddHours(24) && dailyFirewall.Rules().Count == 2,
    "Fresh authorization renews the same client and IP without adding rules");
var expiredDaily = dailyStore.Load(); expiredDaily.Leases.Single().Expires = DateTimeOffset.UtcNow.AddSeconds(-1); dailyStore.Save(expiredDaily); dailyEngine.Cleanup();
Check(dailyFirewall.Rules().Count == 0, "Expired daily permit is removed");
var tooLong = dailyStore.Config(); tooLong.MaxLeaseSeconds = Config.LeaseLimitSeconds + 1;
Reject(() => tooLong.Validate(), "Access window cannot exceed seven days");

// Check policy drift with an in-memory firewall and a separate state journal.
var healthStore = new Store(Path.Combine(temp, "health")); healthStore.Initialize(false);
var healthConfig = healthStore.Config();
healthConfig.RdpPort = 3389;
healthConfig.AllowUdpRdp = false;
healthConfig.TrustedRdpCidrs = ["192.0.2.8/32"];
var healthState = healthStore.Load();
healthState.Migration = new Migration { Config = healthConfig, Confirmed = true };
healthStore.Save(healthState);
var healthFirewall = new MemoryFirewall();
var healthAdmin = new portGate.Host.Administration(new Engine(healthStore, healthFirewall), "unused.exe");
var authorizationRule = new FirewallRule { Name = "KG.Knock", Group = WindowsFirewall.Group, Protocol = 17, Ports = healthConfig.UdpPort.ToString() };
healthFirewall.Put(authorizationRule);
healthFirewall.Put(new FirewallRule { Name = "KG.Trusted.6", Group = WindowsFirewall.Group, Protocol = 6, Ports = "3389", Remote = "192.0.2.8" });
Check(healthAdmin.RefreshHealth(), "Equivalent host addresses pass the health check");
foreach (var remote in new[] { "LocalSubnet", "192.0.2.10-192.0.2.20", "192.0.2.10/9999999999999999999" })
{
    authorizationRule.Remote = remote;
    Check(!healthAdmin.RefreshHealth() && healthAdmin.ProtectionStatus(healthStore.Load(), true).Contains("правило авторизации изменено"),
        "Unrecognized firewall address reports unhealthy without stopping monitoring: " + remote);
}
authorizationRule.Remote = "*";
var preparedLease = new Lease { RuleId = "KG.Lease.audit", Ip = "192.0.2.40", Expires = DateTimeOffset.UtcNow.AddMinutes(1) };
healthState.Leases.Add(preparedLease);
healthStore.Save(healthState);
Check(healthAdmin.RefreshHealth(), "Prepared entry without rules does not interrupt authorization");
var temporaryRule = new FirewallRule { Name = preparedLease.RuleId + ".tcp", Group = WindowsFirewall.Group, Protocol = 6, Ports = "3389", Remote = preparedLease.Ip };
healthFirewall.Put(temporaryRule);
Check(healthAdmin.Health().Contains("неизвестное собственное правило"), "A rule left by incomplete preparation still fails the health check");
preparedLease.Phase = "Committed";
healthStore.Save(healthState);
Check(healthAdmin.RefreshHealth(), "A committed grant with its expected rule passes the health check");
healthFirewall.Remove(temporaryRule.Name);
Check(healthAdmin.Health().Contains("временное правило изменено"), "Missing rule for a committed grant still fails the health check");

foreach (var (command, parameters, usage) in new (string, string[], string)[]
{
    ("clients-create", ["Name"], "clients create NAME SECONDS"),
    ("clients-edit", ["id"], "clients edit ID NAME"),
    ("clients-revoke", [], "clients revoke ID"),
    ("clients-rotate", [], "clients rotate ID"),
    ("clients-export", ["id"], "clients export ID SERVER"),
    ("config-save", [], "config-save FILE.json"),
})
{
    try { dailyAdmin.Dispatch(command, parameters, 0); throw new Exception("Missing arguments were accepted."); }
    catch (ArgumentException error)
    {
        Check(error.Message.Contains(usage, StringComparison.Ordinal), command + " reports its syntax on incomplete input");
    }
}
foreach (var (parameters, usage) in new (string[], string)[]
{
    (["--data"], "--data PATH"),
    (["clients"], "clients list|create"),
    (["clients", "create", "Name"], "clients create NAME SECONDS"),
    (["config-save"], "config-save FILE.json"),
})
{
    string host = Path.Combine(AppContext.BaseDirectory, Deployment.PackagedHostName);
    try { Native.Run(host, parameters); throw new Exception("Incomplete CLI command succeeded."); }
    catch (IOException error)
    {
        Check(error.Message.Contains(usage, StringComparison.Ordinal), "CLI reports syntax before accessing server state: " + parameters[0]);
    }
}

var slowStore = new Store(Path.Combine(temp, "slow-policy")); slowStore.Initialize(false);
var slowState = slowStore.Load(); slowState.Migration = new Migration { Confirmed = true, Config = slowStore.Config() }; slowStore.Save(slowState);
using var slowFirewall = new SlowFirewall();
var slowEngine = new Engine(slowStore, slowFirewall); var slowAdmin = new portGate.Host.Administration(slowEngine, "unused.exe");
var checking = Task.Run(() => slowAdmin.RefreshHealth());
bool entered = slowFirewall.Entered.Wait(TimeSpan.FromSeconds(5));
var creation = Task.Run(() => slowEngine.CreateClient("Not blocked by diagnostics", 300, null));
bool independent = creation.Wait(TimeSpan.FromSeconds(2));
slowFirewall.Release.Set(); await checking; await creation;
Check(entered && independent, "Slow firewall inspection does not hold the store mutex");
// Connection failures must not escape into the service's accept loop.
using (var badFrame = new MemoryStream(BitConverter.GetBytes(Ipc.MaxMessageBytes + 1)))
    await Ipc.ServeConnection(badFrame, _ => throw new Exception("Must not dispatch"), CancellationToken.None);
Check(true, "Invalid IPC frame is rejected without stopping the server");
using (var invalidJson = new MemoryStream())
{
    await Ipc.Write(invalidJson, "{", CancellationToken.None); invalidJson.Position = 0;
    await Ipc.ServeConnection(invalidJson, _ => throw new Exception("Must not dispatch"), CancellationToken.None);
}
Check(true, "Malformed IPC JSON is contained within the connection");
using (var largeReply = new MemoryStream())
{
    await Ipc.Write(largeReply, Json.Write(new RpcRequest("status", [])), CancellationToken.None);
    long responseOffset = largeReply.Position; largeReply.Position = 0;
    await Ipc.ServeConnection(largeReply, _ => new(true, new string('x', Ipc.MaxMessageBytes)), CancellationToken.None);
    largeReply.Position = responseOffset;
    var reply = Json.Read<RpcResponse>(await Ipc.Read(largeReply, CancellationToken.None));
    Check(!reply.Ok && reply.Data.Contains("размер"), "Oversized response returns a bounded error instead of terminating service");
}
using (var nextRequest = new MemoryStream())
{
    await Ipc.Write(nextRequest, Json.Write(new RpcRequest("status", [])), CancellationToken.None);
    long responseOffset = nextRequest.Position; nextRequest.Position = 0;
    await Ipc.ServeConnection(nextRequest, _ => new(true, "alive"), CancellationToken.None);
    nextRequest.Position = responseOffset;
    Check(Json.Read<RpcResponse>(await Ipc.Read(nextRequest, CancellationToken.None)).Data == "alive", "Valid IPC request succeeds after rejected connections");
}
Check(slowAdmin.ProtectionStatus(slowStore.Load(), false).Contains("остановлена"), "Stopped service does not claim a background check is running");
using (var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(1)))
{
    var elapsed = System.Diagnostics.Stopwatch.StartNew();
    Reject(() => Native.PowerShell("Start-Sleep -Seconds 60", 60000, cancellation.Token), "Long-running PowerShell diagnostic can be cancelled");
    Check(cancellation.IsCancellationRequested && elapsed.Elapsed < TimeSpan.FromSeconds(10), "Cancellation completes well within the 45-second stop timeout");
}
CryptographicOperations.ZeroMemory(dailyKey);
Console.WriteLine($"{passed} checks passed. Test data: {temp}");

sealed class SlowFirewall : IFirewall, IDisposable
{
    public ManualResetEventSlim Entered { get; } = new();
    public ManualResetEventSlim Release { get; } = new();
    public List<FirewallRule> Rules() => [];
    public void Put(FirewallRule rule) => throw new NotSupportedException();
    public void Remove(string name) => throw new NotSupportedException();
    public void Enable(string name, bool enabled) => throw new NotSupportedException();
    public FirewallPlan Plan(Config config) { Entered.Set(); if (!Release.Wait(TimeSpan.FromSeconds(10))) throw new TimeoutException(); return new() { RdpPort = 3389 }; }
    public void Dispose() { Entered.Dispose(); Release.Dispose(); }
}
