using System.Net;
using System.Security.Cryptography;

namespace portGate.Core;

public sealed class GrantException(Exception inner) : IOException("Не удалось зафиксировать временное разрешение.", inner);

public sealed class Engine(Store store, IFirewall firewall)
{
    public Store Store => store;
    public IFirewall Firewall => firewall;
    private long rateSecond;
    private int total;
    private readonly Dictionary<string, int> rates = [];
    public void Startup()
    {
        RevokeAll();
        Cleanup();
    }
    public string? Handle(string packet, IPAddress source, DateTimeOffset now)
    {
        if (packet.Length is < 1 or > 1200 || !packet.StartsWith("KG1|", StringComparison.Ordinal) ||
            packet.Any(c => c > 126 || c < 33)) return null;
        string ip = Cidr.Normalize(source).ToString();
        // This engine is invoked serially by the UDP loop.
        long second = Environment.TickCount64 / 1000;
        if (second != rateSecond) { rates.Clear(); total = 0; rateSecond = second; }
        if (total >= 200) return null;
        rates.TryGetValue(ip, out int count);
        if (count >= 20) return null;
        rates[ip] = count + 1;
        total++;
        var fields = packet.Split('|');
        if (fields.Length < 7 || fields[0] != "KG1" || !Protocol.ValidId(fields[2]) || !Protocol.ValidId(fields[3])) return null;
        using var guard = store.Lock();
        Config config = store.Config(); State state = store.Load();
        if (fields[2] != config.ServerId || state.Migration is not { Confirmed: true, Restoring: false }) return null;
        if (config.AllowedKnockCidrs.Length > 0 && !config.AllowedKnockCidrs.Any(c => Cidr.Parse(c).Contains(source))) return null;
        var client = state.Clients.SingleOrDefault(c => c.Id == fields[3] && c.Active(now));
        if (client == null) return null;
        byte[] key = Native.Unprotect(client.ProtectedKey);
        try
        {
            if (!Protocol.Verify(packet, key)) return null;
            long unix = now.ToUnixTimeSeconds();
            state.Requests.RemoveAll(r => r.RetainUntil < unix);
            if (fields[1] == "HELLO" && fields.Length == 7)
            {
                // Retain the KG1 field for existing scripts. Freshness comes from the server's one-time challenge.
                if (!long.TryParse(fields[4], System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out _) || !Hex(fields[5], 32)) return null;
                var existing = state.Requests.FirstOrDefault(r => r.ClientId == client.Id && r.Nonce == fields[5]);
                if (existing != null) return existing.Ip == ip && existing.LeaseId == null && existing.ChallengeExpires >= unix ? Challenge(config, existing, key) : null;
                if (state.Requests.Count >= config.MaxRequests) return null;
                var request = new RequestRecord { ClientId = client.Id, Nonce = fields[5], Ip = ip, Challenge = Protocol.RandomHex(), ChallengeExpires = unix + config.ChallengeSeconds, RetainUntil = unix + config.ChallengeSeconds + 60 };
                state.Requests.Add(request); store.Save(state);
                return Challenge(config, request, key);
            }
            if (fields[1] != "PROOF" || fields.Length != 8 || !Hex(fields[4], 32) || !Hex(fields[5], 32)) return null;
            var proof = state.Requests.FirstOrDefault(r => r.ClientId == client.Id && r.Nonce == fields[4] && r.Challenge == fields[5] && r.Ip == ip);
            if (proof == null || fields[6] != proof.ChallengeExpires.ToString(System.Globalization.CultureInfo.InvariantCulture)) return null;
            if (proof.LeaseId != null)
                return proof.Result != null && state.Leases.Any(l => l.RuleId == proof.LeaseId && l.Phase == "Committed" && l.Expires > now) ? proof.Result : null;
            if (proof.ChallengeExpires < unix) return null;
            var lease = state.Leases.FirstOrDefault(l => l.ClientId == client.Id && l.Ip == ip && l.Phase == "Committed" && l.Expires > now);
            bool newLease = lease == null;
            if (newLease && state.Leases.Count >= config.MaxLeases) return null;
            lease ??= new Lease { ClientId = client.Id, Ip = ip, RuleId = "portgate.Lease." + Protocol.RandomHex() };
            lease.Expires = now.AddSeconds(Math.Min(client.LeaseSeconds, config.MaxLeaseSeconds));
            if (client.Expires is { } expiry && expiry < lease.Expires) lease.Expires = expiry;
            proof.LeaseId = lease.RuleId;
            try
            {
                if (newLease)
                {
                    // Persist the intent before creating any rule.
                    state.Leases.Add(lease);
                    store.Save(state);
                    AddLease(lease, config, state.Migration.Config.RdpPort);
                }
                lease.Phase = "Committed";
                client.LastIp = ip; client.LastRequest = now;
                proof.Result = Protocol.Pack($"KG1|RESULT|{config.ServerId}|{client.Id}|{proof.Nonce}|{proof.Challenge}|{lease.Expires.ToUnixTimeSeconds()}|{state.Migration.Config.RdpPort}", key);
                store.Save(state);
            }
            catch (Exception failure)
            {
                if (newLease) firewall.RemoveOwned(LeaseRules(lease));
                throw new GrantException(failure);
            }
            store.TryLog("AccessGranted", $"client={client.Id}; ip={ip}; until={lease.Expires:O}");
            return proof.Result;
        }
        finally { CryptographicOperations.ZeroMemory(key); }
    }
    private static bool Hex(string value, int length) => value.Length == length && value.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');
    private static string Challenge(Config config, RequestRecord r, byte[] key) => Protocol.Pack($"KG1|CHALLENGE|{config.ServerId}|{r.ClientId}|{r.Nonce}|{r.Challenge}|{r.ChallengeExpires}|{r.Ip}", key);
    private void AddLease(Lease lease, Config config, int port)
    {
        firewall.Put(new() { Name = lease.RuleId + ".tcp", Group = WindowsFirewall.Group, Ports = port.ToString(), Protocol = 6, Remote = lease.Ip });
        if (config.AllowUdpRdp) firewall.Put(new() { Name = lease.RuleId + ".udp", Group = WindowsFirewall.Group, Ports = port.ToString(), Protocol = 17, Remote = lease.Ip });
    }
    private static string[] LeaseRules(Lease lease) => [lease.RuleId + ".tcp", lease.RuleId + ".udp"];
    private IEnumerable<string> OwnedLeaseRules() => firewall.Rules().Where(r => r.Group == WindowsFirewall.Group && r.Name.StartsWith("portgate.Lease.", StringComparison.Ordinal)).Select(r => r.Name);
    public void RevokeAll()
    {
        using var guard = store.Lock(); var state = store.Load();
        firewall.RemoveOwned(OwnedLeaseRules());
        state.Leases.Clear(); foreach (var r in state.Requests) r.Result = null; store.Save(state);
    }
    public void RevokeLease(string ruleId)
    {
        using var guard = store.Lock();
        var state = store.Load();
        var lease = state.Leases.SingleOrDefault(l => l.RuleId == ruleId)
            ?? throw new InvalidOperationException("Временное разрешение уже истекло или было отозвано.");
        firewall.RemoveOwned(LeaseRules(lease));
        state.Leases.Remove(lease);
        foreach (var request in state.Requests.Where(r => r.LeaseId == ruleId)) request.Result = null;
        store.Save(state);
        store.TryLog("LeaseRevoked", $"client={lease.ClientId}; ip={lease.Ip}");
    }
    public void Cleanup(bool sweepOrphans = true, bool attemptRollback = true)
    {
        string? rollback;
        using (store.Lock())
        {
            State state;
            try { state = store.Load(); }
            catch { firewall.RemoveOwned(OwnedLeaseRules()); throw; }
            var now = DateTimeOffset.UtcNow;
            var activeClients = state.Clients.Where(c => c.Active(now)).Select(c => c.Id).ToHashSet();
            var expired = state.Leases.Where(l => l.Phase != "Committed" || l.Expires <= now || !activeClients.Contains(l.ClientId)).ToHashSet();
            var retained = state.Leases.Where(l => !expired.Contains(l))
                .GroupBy(l => (l.ClientId, l.Ip)).Select(g => g.MaxBy(l => l.Expires)!).ToHashSet();
            expired.UnionWith(state.Leases.Where(l => !retained.Contains(l)));
            var remove = expired.SelectMany(LeaseRules);
            if (sweepOrphans)
            {
                var known = retained.SelectMany(LeaseRules).ToHashSet();
                remove = remove.Concat(OwnedLeaseRules().Where(name => !known.Contains(name)));
            }
            firewall.RemoveOwned(remove);
            int removedLeases = state.Leases.RemoveAll(expired.Contains);
            int removedRequests = state.Requests.RemoveAll(r => r.RetainUntil < now.ToUnixTimeSeconds());
            if (removedLeases + removedRequests > 0) store.Save(state);
            rollback = state.Migration is { Confirmed: false } migration && migration.RollbackAt <= now ? migration.Generation : null;
        }
        if (attemptRollback && rollback != null) Restore(rollback);
    }
    public ClientRecord CreateClient(string name, int seconds, DateTimeOffset? expires)
    {
        using var guard = store.Lock(); var config = store.Config(); var state = store.Load();
        if (state.Clients.Count >= config.MaxClients || name.Length is < 1 or > 100 || seconds < 30 || seconds > config.MaxLeaseSeconds || expires <= DateTimeOffset.UtcNow) throw new ArgumentException("Некорректный клиент или достигнут лимит.");
        var client = new ClientRecord { Name = name, LeaseSeconds = seconds, Expires = expires, ProtectedKey = Native.Protect(RandomNumberGenerator.GetBytes(32)) };
        state.Clients.Add(client); store.Save(state); return client;
    }
    public void ChangeClient(string id, bool rotate)
    {
        using var guard = store.Lock(); var state = store.Load();
        var client = state.Clients.Single(c => c.Id == id);
        if (rotate) { client.ProtectedKey = Native.Protect(RandomNumberGenerator.GetBytes(32)); client.Enabled = true; } else client.Enabled = false;
        RemoveClientAccess(state, id);
        store.Save(state);
        store.Log(rotate ? "ClientRotated" : "ClientRevoked", id);
    }
    public void DeleteClient(string id)
    {
        using var guard = store.Lock();
        var state = store.Load();
        var client = state.Clients.SingleOrDefault(c => c.Id == id)
            ?? throw new InvalidOperationException("Ключ уже удалён или не найден.");
        RemoveClientAccess(state, id);
        state.Clients.Remove(client);
        store.Save(state);
        store.TryLog("ClientDeleted", id);
    }
    private void RemoveClientAccess(State state, string id)
    {
        firewall.RemoveOwned(state.Leases.Where(l => l.ClientId == id).SelectMany(LeaseRules));
        state.Leases.RemoveAll(l => l.ClientId == id);
        state.Requests.RemoveAll(r => r.ClientId == id);
    }
    public void Apply(Action scheduleRollback, int session) => Apply(_ => scheduleRollback(), session);

    public void UpdateTrustedAllowlist(Config next, CancellationToken token = default)
    {
        next.Validate();
        using var policy = store.LockPolicy();
        Config previous;
        Migration migration;
        using (store.Lock())
        {
            migration = ConfirmedPolicy(store.Load());
            previous = store.Config();
            ValidateActiveConfig(previous, next);
        }

        string previousRemote = string.Join(",", migration.Config.TrustedRdpCidrs);
        string remote = string.Join(",", next.TrustedRdpCidrs);
        bool changed = !next.TrustedRdpCidrs.SequenceEqual(migration.Config.TrustedRdpCidrs);
        var planned = Json.Read<Config>(Json.Write(migration.Config));
        planned.TrustedRdpCidrs = next.TrustedRdpCidrs;
        planned.ServerAddress = next.ServerAddress;
        planned.LeaseSeconds = next.LeaseSeconds;
        planned.MaxLeaseSeconds = next.MaxLeaseSeconds;
        if (changed)
        {
            var plan = firewall.Plan(planned, token);
            if (!plan.Safe || plan.Disable.Count > 0 || plan.RdpPort != planned.RdpPort)
                throw new InvalidOperationException("Живое обновление белого списка отклонено. " +
                    string.Join("\n", plan.Conflicts.Concat(plan.Disable.Select(r => r.Name))));
        }

        using var guard = store.Lock();
        var latest = store.Load();
        var active = ConfirmedPolicy(latest);
        if (active.Generation != migration.Generation)
            throw new InvalidOperationException("Состояние политики изменилось; требуется новая проверка.");
        token.ThrowIfCancellationRequested();
        var updated = new List<string>();
        string[] names = planned.AllowUdpRdp ? ["portgate.Trusted.6", "portgate.Trusted.17"] : ["portgate.Trusted.6"];
        if (changed)
        {
            var rules = firewall.Rules();
            foreach (string name in names)
            {
                var rule = rules.SingleOrDefault(r => r.Group == WindowsFirewall.Group && r.Name == name);
                int protocol = name == "portgate.Trusted.6" ? 6 : 17;
                if (rule == null || !rule.Enabled || rule.Action != 1 || rule.Direction != 1 ||
                    rule.Protocol != protocol || rule.Ports != planned.RdpPort.ToString() || rule.Profiles != 7 ||
                    rule.Application != "" || rule.Service != "" ||
                    Cidr.NormalizeFirewallAddresses(rule.Remote) != Cidr.NormalizeFirewallAddresses(previousRemote))
                    throw new InvalidOperationException("Защита нарушена: белый список изменён");
            }
        }
        bool configSaved = false;
        try
        {
            if (changed)
                foreach (string name in names)
                {
                    firewall.UpdateRemote(name, remote);
                    updated.Add(name);
                }
            active.Config = planned;
            store.SaveConfig(next);
            configSaved = true;
            store.Save(latest);
        }
        catch (Exception failure)
        {
            var rollbackErrors = new List<Exception>();
            foreach (string name in Enumerable.Reverse(updated))
            {
                try { firewall.UpdateRemote(name, previousRemote); }
                catch (Exception error) { rollbackErrors.Add(error); }
            }
            if (configSaved)
            {
                try { Store.Atomic(store.ConfigPath, Json.Write(previous), false); }
                catch (Exception error) { rollbackErrors.Add(error); }
            }
            if (rollbackErrors.Count > 0)
            {
                store.TryLog("AllowlistRollbackIncomplete", string.Join(" | ", rollbackErrors.Select(e => e.Message)));
                throw new AggregateException("Не удалось полностью откатить обновление белого списка: " +
                    string.Join(" | ", rollbackErrors.Select(e => e.Message)), [failure, .. rollbackErrors]);
            }
            throw;
        }
        if (changed) store.TryLog("AllowlistUpdated", string.Join(", ", next.TrustedRdpCidrs));
    }

    private static Migration ConfirmedPolicy(State state) =>
        state.Migration is { Confirmed: true, Applying: false, Restoring: false, RestoreProblems.Length: 0 } migration
            ? migration : throw new InvalidOperationException("Настройки доступны после подтверждения защиты или завершения восстановления.");

    private static void ValidateActiveConfig(Config previous, Config next)
    {
        if (next.TrustedRdpCidrs.Length == 0)
            throw new InvalidOperationException("При действующей защите белый список не может быть пустым.");
        var permitted = Json.Read<Config>(Json.Write(previous));
        permitted.ServerAddress = next.ServerAddress;
        permitted.LeaseSeconds = next.LeaseSeconds;
        permitted.MaxLeaseSeconds = next.MaxLeaseSeconds;
        permitted.TrustedRdpCidrs = next.TrustedRdpCidrs;
        if (Json.Write(permitted) != Json.Write(next))
            throw new InvalidOperationException("Для изменения сети или правил сначала восстановите прежние правила. Адрес сервера и окна доступа можно менять без восстановления.");
    }

    public DateTimeOffset Apply(Action<DateTimeOffset> scheduleRollback, int session, CancellationToken token = default)
    {
        Config config;
        using (store.Lock()) config = store.Config();
        config.Validate();
        string originalConfig = Json.Write(config);
        if (config.TrustedRdpCidrs.Length == 0) throw new InvalidOperationException("Укажите постоянный белый список до применения.");
        var plan = firewall.Plan(config, token);
        if (!plan.Safe) throw new InvalidOperationException(string.Join("\n", plan.Conflicts));
        config.RdpPort = plan.RdpPort;
        var migration = new Migration { Config = config, DisabledRules = [], InitialSession = session, Applying = true, RollbackAt = DateTimeOffset.UtcNow.AddMinutes(4) };
        bool journaled = false;
        try
        {
            using (store.LockPolicy())
            {
                using (store.Lock())
                {
                    var state = store.Load();
                    if (state.Migration != null) throw new InvalidOperationException("Сначала восстановите прежние правила либо подтвердите незавершённое применение.");
                    if (Json.Write(store.Config()) != originalConfig) throw new InvalidOperationException("Настройки изменились во время проверки. Примените защиту заново.");
                    state.Migration = migration;
                    store.Save(state);
                    journaled = true;
                }
                // The independent deadline is armed before the first firewall mutation.
                scheduleRollback(migration.RollbackAt);
                token.ThrowIfCancellationRequested();
                firewall.Put(new() { Name = "portgate.Authorization", Group = WindowsFirewall.Group, Ports = config.UdpPort.ToString(), Protocol = 17, Remote = config.AllowedKnockCidrs.Length == 0 ? "*" : string.Join(",", config.AllowedKnockCidrs) });
                foreach (int proto in config.AllowUdpRdp ? new[] { 6, 17 } : new[] { 6 })
                    firewall.Put(new() { Name = "portgate.Trusted." + proto, Group = WindowsFirewall.Group, Ports = config.RdpPort.ToString(), Protocol = proto, Remote = string.Join(",", config.TrustedRdpCidrs) });
                foreach (var rule in plan.Disable)
                {
                    token.ThrowIfCancellationRequested();
                    var current = firewall.Find(rule);
                    if (current == null || !current.Enabled || current.Fingerprint != rule.Fingerprint)
                        throw new InvalidOperationException("Правило изменилось во время применения: " + rule.Name);
                    using (store.Lock())
                    {
                        var state = store.Load();
                        state.Migration!.DisabledRules.Add(rule);
                        store.Save(state);
                    }
                    firewall.Enable(rule.Identity, false);
                }
            }
            var after = firewall.Plan(config, token);
            if (!after.Safe || after.Disable.Count > 0) throw new InvalidOperationException("Не удалось подтвердить итоговую политику.");
            using (store.LockPolicy())
            {
                using (store.Lock())
                {
                    var current = store.Load().Migration;
                    if (current?.Generation != migration.Generation || current.Restoring || current.RollbackAt <= DateTimeOffset.UtcNow)
                        throw new InvalidOperationException("Применение прервалось. Проверьте состояние защиты.");
                }
                DateTimeOffset deadline = DateTimeOffset.UtcNow.AddSeconds(120);
                scheduleRollback(deadline);
                using var guard = store.Lock();
                var state = store.Load();
                var pending = state.Migration;
                if (pending?.Generation != migration.Generation || pending.Restoring || pending.RollbackAt <= DateTimeOffset.UtcNow)
                    throw new InvalidOperationException("Применение прервалось. Проверьте состояние защиты.");
                pending.Applying = false;
                pending.RollbackAt = deadline;
                store.Save(state);
                store.TryLog("PolicyAppliedPending", migration.Generation);
                return deadline;
            }
        }
        catch (Exception failure)
        {
            if (journaled)
            {
                try { Restore(migration.Generation, onlyPending: false); }
                catch (Exception rollback) { throw new InvalidOperationException($"{failure.Message} Откат не завершён. {rollback.Message}", failure); }
            }
            throw;
        }
    }
    public void Confirm(int session, CancellationToken token = default)
    {
        Migration m;
        using (store.Lock()) m = GetPendingMigration(store.Load());
        if (!RemoteSession.IsNew(session, m.InitialSession, m.Started)) throw new InvalidOperationException("Подтвердите из нового RDP-сеанса, подключённого после применения.");
        var plan = firewall.Plan(m.Config, token);
        if (!plan.Safe || plan.Disable.Count != 0) throw new InvalidOperationException("Конфликт эффективной политики.");
        using var policy = store.LockPolicy();
        using var guard = store.Lock();
        var state = store.Load();
        var pending = GetPendingMigration(state);
        if (pending.Generation != m.Generation) throw new InvalidOperationException("Ожидающая подтверждения политика изменилась.");
        pending.Confirmed = true;
        store.Save(state);
        store.TryLog("PolicyConfirmed", pending.Generation);
    }
    private static Migration GetPendingMigration(State state)
    {
        var migration = state.Migration;
        if (migration is not { Confirmed: false, Applying: false, Restoring: false })
            throw new InvalidOperationException("Нет правил, ожидающих подтверждения. Если срок истёк, примените защиту заново.");
        if (migration.RollbackAt <= DateTimeOffset.UtcNow) throw new InvalidOperationException("Время подтверждения истекло.");
        return migration;
    }
    public void Restore() => Restore(null, onlyPending: false);

    private void Restore(string? generation, bool onlyPending = true)
    {
        using var policy = store.LockPolicy();
        Migration migration;
        using (store.Lock())
        {
            var state = store.Load();
            if (state.Migration is not { } current || generation != null && current.Generation != generation) return;
            if (onlyPending && (current.Confirmed || current.RollbackAt > DateTimeOffset.UtcNow)) return;
            current.Confirmed = false;
            current.Restoring = true;
            current.RollbackAt = DateTimeOffset.UtcNow.AddMinutes(1);
            store.Save(state);
            migration = current;
        }
        var unresolved = new List<FirewallRule>();
        var problems = new List<string>();
        foreach (var rule in migration.DisabledRules)
        {
            try
            {
                var found = firewall.Find(rule);
                if (found == null || found.Fingerprint != rule.Fingerprint)
                    throw new InvalidOperationException("Исходное правило удалено или изменено.");
                if (found.Enabled != rule.Enabled) firewall.Enable(rule.Identity, rule.Enabled);
            }
            catch (Exception error)
            {
                unresolved.Add(rule);
                problems.Add($"{rule.Name} [{rule.Identity}] — {error.Message}");
            }
        }
        using var guard = store.Lock();
        var latest = store.Load();
        latest.Migration!.DisabledRules = unresolved;
        latest.Migration.RestoreProblems = problems.ToArray();
        store.Save(latest);
        if (problems.Count != 0)
        {
            store.TryLog("PolicyRestoreIncomplete", string.Join("\n", problems));
            if (!onlyPending) throw new InvalidOperationException("Восстановите перечисленные правила вручную и повторите откат. " + string.Join("\n", problems));
            return;
        }

        firewall.RemoveOwned(firewall.Rules().Where(r => r.Group == WindowsFirewall.Group).Select(r => r.Name));
        latest.Leases.Clear();
        latest.Migration = null;
        foreach (var request in latest.Requests) request.Result = null;
        store.Save(latest);
        store.TryLog("PolicyRestored", "Прежние правила восстановлены.");
    }
}
