using System.Diagnostics;
using System.Security;
using portGate.Core;

namespace portGate.Host;
public sealed class Administration(Engine engine, string executable)
{
    public const string ServiceName = Deployment.ServiceName;
    private const string CleanupTask = "KnockGate.Cleanup";
    private const string RollbackTask = "KnockGate.Rollback";
    private Store Store => engine.Store;
    private string? checkedGeneration;
    private string protection = "Проверка политики выполняется";
    private DateTimeOffset? checkedAt;
    public bool RefreshHealth(CancellationToken cancellationToken = default)
    {
        string? generation; using (Store.Lock()) generation = Store.Load().Migration?.Generation;
        string result = Health(cancellationToken);
        using var guard = Store.Lock();
        if (Store.Load().Migration?.Generation != generation) return false;
        protection = result; checkedGeneration = generation; checkedAt = DateTimeOffset.UtcNow;
        return result == "RDP ограничен по IP";
    }
    public string Dispatch(string command, string[] args, int session, CancellationToken cancellationToken = default)
    {
        CommandArguments.Validate(command, args.Length);
        if (command is "diagnose" or "plan")
        {
            Config snapshot; using (Store.Lock()) snapshot = Store.Config();
            return Json.Write(engine.Firewall.Plan(snapshot, cancellationToken));
        }
        if (command == "apply")
        {
            DateTimeOffset deadline = engine.Apply(RegisterRollback, session, cancellationToken);
            return $"Правила применены. Подтвердите из нового RDP-сеанса до {deadline.ToLocalTime():HH:mm:ss}.";
        }
        if (command == "confirm")
        {
            engine.Confirm(session, cancellationToken);
            return "Политика подтверждена.";
        }
        if (command == "restore")
        {
            engine.Restore();
            return "Прежние правила восстановлены.";
        }
        switch (command)
        {
            case "cleanup": engine.Cleanup(); return "Очистка завершена.";
            case "leases-revoke": engine.RevokeAll(); return "Временные разрешения отозваны.";
            case "lease-revoke":
                engine.RevokeLease(args[0]);
                return "Разрешение отозвано. Клиент может запросить доступ заново.";
            case "clients-create":
                var client = engine.CreateClient(args[0], int.Parse(args[1]), args.Length > 2 && args[2] != "" ? DateTimeOffset.Parse(args[2], System.Globalization.CultureInfo.InvariantCulture) : null);
                return client.Id;
            case "clients-revoke": engine.ChangeClient(args[0], false); return "Доступ отозван.";
            case "clients-rotate": engine.ChangeClient(args[0], true); return "Ключ перевыпущен. Старые скрипты недействительны.";
            case "clients-export": return ScriptExporter.Export(Store, args[0], args[1], args.Length > 2 && args[2] == "true", args.Length > 3 ? args[3] : "bat");
        }
        using var guard = Store.Lock();
        switch (command)
        {
            case "status":
            {
                var state = Store.Load(); var config = Store.Config();
                using var installed = System.ServiceProcess.ServiceController.GetServices().FirstOrDefault(s => s.ServiceName == ServiceName);
                string health = ProtectionStatus(state, installed?.Status == System.ServiceProcess.ServiceControllerStatus.Running);
                var clientNames = state.Clients.ToDictionary(c => c.Id, c => c.Name);
                return Json.Write(new
                {
                    serverId = config.ServerId, service = installed?.Status.ToString() ?? "Не установлена",
                    protection = health, healthCheckedAt = checkedAt, policyConfigured = state.Migration != null,
                    pendingConfirmation = state.Migration is { Confirmed: false, Applying: false, Restoring: false },
                    rollbackAt = state.Migration?.RollbackAt, serverNow = DateTimeOffset.UtcNow,
                    hasTrustedSources = config.TrustedRdpCidrs.Length > 0,
                    udpPort = config.UdpPort, rdpPort = state.Migration?.Config.RdpPort,
                    leases = state.Leases.Select(l => new { clientName = clientNames.GetValueOrDefault(l.ClientId, l.ClientId), l.Ip, l.Expires, l.Phase, l.ClientId, l.RuleId }),
                    clients = state.Clients.Select(c => new { c.Name, active = c.Active(DateTimeOffset.UtcNow), c.Enabled, c.LeaseSeconds, c.Expires, c.LastIp, c.LastRequest, c.Created, c.Id })
                });
            }
            case "config": return Json.Write(Store.Config());
            case "config-save":
                var next = Json.Read<Config>(args[0]); next.Validate();
                var previous = Store.Config();
                var current = Store.Load();
                var permitted = Json.Read<Config>(Json.Write(previous));
                permitted.ServerAddress = next.ServerAddress; permitted.LeaseSeconds = next.LeaseSeconds; permitted.MaxLeaseSeconds = next.MaxLeaseSeconds;
                if (current.Migration != null && Json.Write(permitted) != Json.Write(next)) throw new InvalidOperationException("Для изменения сети или правил сначала восстановите прежние правила. Адрес сервера и окна доступа можно менять без восстановления.");
                if (next.UdpPort != previous.UdpPort || next.ListenAddress != previous.ListenAddress)
                { using var test = new System.Net.Sockets.UdpClient(new System.Net.IPEndPoint(System.Net.IPAddress.Parse(next.ListenAddress), next.UdpPort)); }
                Store.SaveConfig(next);
                return "Настройки сохранены. Адрес и окна доступа действуют для новых скриптов и запросов; существующие разрешения сохраняют свой срок. При изменении сети перезапустите службу перед применением.";
            case "clients-list": return Json.Write(Store.Load().Clients.Select(c => new { c.Id, c.Name, c.Enabled, c.Expires, c.Created, c.LastIp, c.LastRequest, c.LeaseSeconds }));
            case "clients-edit":
                var editState = Store.Load(); var edit = editState.Clients.Single(c => c.Id == args[0]);
                if (args[1].Length is < 1 or > 100) throw new ArgumentException("Некорректное имя.");
                if (args.Length > 3) { int seconds = int.Parse(args[3]); if (seconds < 30 || seconds > Store.Config().MaxLeaseSeconds) throw new ArgumentException("Окно превышает допустимые пределы."); edit.LeaseSeconds = seconds; }
                edit.Name = args[1]; edit.Expires = args.Length > 2 && args[2] != "" ? DateTimeOffset.Parse(args[2], System.Globalization.CultureInfo.InvariantCulture) : null; Store.Save(editState); return "Клиент изменён.";
            case "events":
                string log = Path.Combine(Store.Root, "events.jsonl"); return File.Exists(log) ? string.Join("\n", File.ReadLines(log).TakeLast(100)) : "Событий нет.";
            default: throw new ArgumentException("Неизвестная команда.");
        }
    }
    public string ProtectionStatus(State state, bool serviceRunning) => state.Migration switch
    {
        null => "Не настроено",
        { RestoreProblems.Length: > 0 } m => "Откат не завершён. " + string.Join("\n", m.RestoreProblems),
        { Restoring: true } => "Восстанавливаются прежние правила",
        { Applying: true } => "Применение и проверка правил",
        _ when !serviceRunning => "Служба остановлена; актуальность политики не проверена",
        { Confirmed: false } => "Ожидается подтверждение нового RDP-сеанса",
        { } m when checkedGeneration == m.Generation => protection,
        _ => "Проверка политики выполняется"
    };
    public string Health(CancellationToken cancellationToken = default)
    {
        State state;
        using (Store.Lock()) state = Store.Load();
        if (state.Migration == null) return "Не настроено";
        if (!state.Migration.Confirmed) return "Ожидается подтверждение нового RDP-сеанса";
        var c = state.Migration.Config;
        try { c.Validate(); }
        catch (InvalidDataException error) { return "Защита нарушена: " + error.Message; }
        var plan = engine.Firewall.Plan(c, cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();
        using var guard = Store.Lock();
        var latest = Store.Load();
        if (latest.Migration?.Generation != state.Migration.Generation || latest.Migration.Confirmed != true) return "Состояние политики изменилось; требуется новая проверка";
        state = latest;
        if (!plan.Safe || plan.Disable.Count > 0) return "Защита нарушена: " + string.Join("; ", plan.Conflicts.Concat(plan.Disable.Select(r => r.Name)));
        var rules = engine.Firewall.Rules();
        bool Match(string name, int protocol, string ports, string remote)
        {
            var owned = rules.Where(rule => rule.Name == name && rule.Group == WindowsFirewall.Group)
                .Take(2).ToArray();
            if (owned.Length != 1) return false;
            var rule = owned[0];
            if (!rule.Enabled || rule.Action != 1 || rule.Direction != 1 || rule.Protocol != protocol ||
                rule.Ports != ports || rule.Profiles != 7 || rule.Application != "" || rule.Service != "") return false;

            try
            {
                return Cidr.NormalizeFirewallAddresses(rule.Remote) == Cidr.NormalizeFirewallAddresses(remote);
            }
            catch (Exception error) when (error is FormatException or OverflowException)
            {
                return false;
            }
        }
        if (!Match("KG.Knock", 17, c.UdpPort.ToString(), c.AllowedKnockCidrs.Length == 0 ? "*" : string.Join(",", c.AllowedKnockCidrs))) return "Защита нарушена: правило авторизации изменено";
        foreach (int proto in c.AllowUdpRdp ? new[] { 6, 17 } : new[] { 6 })
            if (!Match("KG.Trusted." + proto, proto, c.RdpPort.ToString(), string.Join(",", c.TrustedRdpCidrs))) return "Защита нарушена: белый список изменён";
        // Every own permit must correspond to the current journal; extra own rules are also a drift.
        var names = new HashSet<string> { "KG.Knock", "KG.Trusted.6" };
        if (c.AllowUdpRdp) names.Add("KG.Trusted.17");
        // A Prepared entry can remain briefly after grant creation failed and its rules were removed.
        // An actual leftover rule must still be caught as an unexpected owned rule.
        foreach (var lease in state.Leases.Where(lease => lease.Phase == "Committed"))
        {
            names.Add(lease.RuleId + ".tcp"); if (c.AllowUdpRdp) names.Add(lease.RuleId + ".udp");
            if (!Match(lease.RuleId + ".tcp", 6, c.RdpPort.ToString(), lease.Ip) || c.AllowUdpRdp && !Match(lease.RuleId + ".udp", 17, c.RdpPort.ToString(), lease.Ip)) return "Защита нарушена: временное правило изменено";
        }
        if (rules.Any(r => r.Group == WindowsFirewall.Group && !names.Contains(r.Name))) return "Защита нарушена: неизвестное собственное правило";
        return "RDP ограничен по IP";
    }
    private string TaskXml(DateTimeOffset? rollbackAt)
    {
        string exe = SecurityElement.Escape(executable)!;
        string args = SecurityElement.Escape("cleanup --data \"" + Store.Root + "\"")!;
        var deadline = rollbackAt ?? DateTimeOffset.UtcNow.AddSeconds(5);
        long unix = deadline.ToUnixTimeSeconds();
        if (DateTimeOffset.FromUnixTimeSeconds(unix) < deadline) unix++;
        string time = DateTimeOffset.FromUnixTimeSeconds(unix).ToString("yyyy-MM-ddTHH:mm:sszzz", System.Globalization.CultureInfo.InvariantCulture);
        string repetition = rollbackAt.HasValue ? "" : "<Repetition><Interval>PT1M</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition>";
        return $"<?xml version=\"1.0\" encoding=\"UTF-16\"?><Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\"><Triggers><TimeTrigger>{repetition}<StartBoundary>{time}</StartBoundary><Enabled>true</Enabled></TimeTrigger><BootTrigger><Enabled>true</Enabled></BootTrigger></Triggers><Principals><Principal id=\"Author\"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals><Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><StartWhenAvailable>true</StartWhenAvailable><ExecutionTimeLimit>PT2M</ExecutionTimeLimit><Enabled>true</Enabled></Settings><Actions Context=\"Author\"><Exec><Command>{exe}</Command><Arguments>{args}</Arguments></Exec></Actions></Task>";
    }
    private void RegisterTask(string name, DateTimeOffset? rollbackAt)
    {
        string path = Path.Combine(Store.Root, name + ".xml"); File.WriteAllText(path, TaskXml(rollbackAt), System.Text.Encoding.Unicode);
        Native.Run("schtasks.exe", ["/Create", "/TN", name, "/XML", path, "/F"]);
        Native.Run("schtasks.exe", ["/Query", "/TN", name]);
    }
    public void RegisterCleanup() => RegisterTask(CleanupTask, null);
    private void RegisterRollback(DateTimeOffset deadline) => RegisterTask(RollbackTask, deadline);
    public void Install()
    {
        Store.RequireAdmin();
        string protectedRoot = Path.GetFullPath(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles)).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        if (!Path.GetFullPath(executable).StartsWith(protectedRoot, StringComparison.OrdinalIgnoreCase) || !Path.GetFileName(executable).Equals(Deployment.InstalledHostName, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Для установки запустите portGate.Host.exe из полностью распакованного релизного архива.");
        if (executable.Contains('"') || Store.Root.Contains('"')) throw new ArgumentException("Некорректный путь.");
        bool exists = System.ServiceProcess.ServiceController.GetServices().Any(s => s.ServiceName == ServiceName);
        Native.Run("sc.exe", [exists ? "config" : "create", ServiceName, "binPath=", $"\"{executable}\" service --data \"{Store.Root}\"", "start=", "auto", "obj=", "LocalSystem", "DisplayName=", "portGate RDP Gate"]);
        Native.Run("sc.exe", ["failure", ServiceName, "reset=", "86400", "actions=", "restart/5000/restart/15000/restart/60000"]);
        RegisterCleanup();
    }
    public void Uninstall(bool restore)
    {
        Store.RequireAdmin();
        if (System.ServiceProcess.ServiceController.GetServices().Any(s => s.ServiceName == ServiceName))
        {
            using var service = new System.ServiceProcess.ServiceController(ServiceName);
            if (service.Status != System.ServiceProcess.ServiceControllerStatus.Stopped) { service.Stop(); service.WaitForStatus(System.ServiceProcess.ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(45)); }
        }
        if (restore) engine.Restore(); else
        {
            engine.RevokeAll(); engine.Firewall.Remove("KG.Knock");
            using var guard = Store.Lock(); var state = Store.Load();
            if (state.Migration is { Confirmed: false }) throw new InvalidOperationException("Сначала восстановите незавершённое применение.");
        }
        RemoveRegistration();
    }

    public static void RemoveRegistration()
    {
        foreach (string task in new[] { CleanupTask, RollbackTask })
        {
            try { Native.Run("schtasks.exe", ["/Query", "/TN", task]); }
            catch (IOException) { continue; }
            Native.Run("schtasks.exe", ["/Delete", "/TN", task, "/F"]);
        }
        if (System.ServiceProcess.ServiceController.GetServices().Any(s => s.ServiceName == ServiceName)) Native.Run("sc.exe", ["delete", ServiceName]);
    }
}
