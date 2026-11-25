using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.ServiceProcess;
using System.Text;
using portGate.Core;
using portGate.Host;

return await Entry.Run(args);

internal static class Entry
{
    public static async Task<int> Run(string[] input)
    {
        if (Console.IsOutputRedirected) Console.SetOut(new StreamWriter(Console.OpenStandardOutput(), new UTF8Encoding(false)) { AutoFlush = true });
        else Console.OutputEncoding = new UTF8Encoding(false);
        if (Console.IsErrorRedirected) Console.SetError(new StreamWriter(Console.OpenStandardError(), new UTF8Encoding(false)) { AutoFlush = true });
        try
        {
            var args = input.ToList();
            string root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), Deployment.InstallationDirectoryName);
            int data = args.IndexOf("--data");
            if (data >= 0)
            {
                if (data + 1 >= args.Count || string.IsNullOrWhiteSpace(args[data + 1]) || args[data + 1] == "--data")
                    throw new ArgumentException("Использование: --data PATH");
                root = args[data + 1];
                args.RemoveRange(data, 2);
                if (args.Contains("--data")) throw new ArgumentException("Укажите --data PATH один раз.");
            }
            if (args.Count == 0 || args[0] is "help" or "--help") { Console.WriteLine(Help); return 0; }
            string command = args[0];
            string[] rest = args.Skip(1).ToArray();
            if (command == "clients")
            {
                if (rest.Length == 0) throw new ArgumentException("Использование: clients list|create|edit|revoke|rotate|export");
                command = "clients-" + rest[0];
                rest = rest[1..];
            }
            CommandArguments.Validate(command, rest.Length, fromConsole: true);
            var store = new Store(root);
            string exe = Environment.ProcessPath ?? throw new IOException("Неизвестен путь запуска.");
            var engine = new Engine(store, new WindowsFirewall()); var admin = new Administration(engine, exe);
            if (command == "status" && !File.Exists(store.ConfigPath)) { Console.WriteLine(Json.Write(new { protection = "Не настроено", service = "Не установлена", udpPort = 51888, clients = Array.Empty<object>(), leases = Array.Empty<object>() })); return 0; }
            if (command == "init") { store.Initialize(true); Console.WriteLine(store.ConfigPath); return 0; }
            Store.RequireAdmin();
            if (command == "service") { ServiceBase.Run(new GateService(store, engine, admin)); return 0; }
            if (command == "run") { using var cancel = new CancellationTokenSource(); Console.CancelKeyPress += (_, e) => { e.Cancel = true; cancel.Cancel(); }; await Runtime.Run(store, engine, admin, cancel.Token); return 0; }
            if (command == "install")
            {
                string destination = Deployment.InstalledHost;
                if (!Path.GetFullPath(exe).Equals(Path.GetFullPath(destination), StringComparison.OrdinalIgnoreCase))
                {
                    using var installLock = store.LockDeployment();
                    foreach (var p in Process.GetProcessesByName("portgate.Manager"))
                    {
                        using (p) if (p.MainModule?.FileName is string path && path.StartsWith(Path.GetDirectoryName(destination)! + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                            throw new IOException("Закройте установленную панель portGate перед обновлением. Новую панель из распакованного ZIP можно оставить открытой.");
                    }
                    using var update = Deployment.StagePackage(AppContext.BaseDirectory, Path.GetDirectoryName(destination)!);
                    using var existing = ServiceController.GetServices().FirstOrDefault(s => s.ServiceName == Administration.ServiceName);
                    bool restart = existing?.Status is ServiceControllerStatus.Running or ServiceControllerStatus.StartPending;
                    bool switched = false;
                    try
                    {
                        if (restart) existing!.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(45));
                        if (existing != null && existing.Status != ServiceControllerStatus.Stopped)
                        {
                            existing.Stop();
                            existing.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(45));
                        }
                        string installed = update.Activate();
                        switched = true;
                        if (existing == null) Console.WriteLine(Native.Run(installed, new[] { "install", "--data", root }, 90000));
                        if (restart)
                        {
                            existing!.Start();
                            existing.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(45));
                        }
                        update.Commit();
                        if (existing != null) Console.WriteLine(restart ? "Служба обновлена и запущена." : "Служба обновлена и остановлена.");
                    }
                    catch (Exception failure)
                    {
                        try
                        {
                            if (switched && existing != null)
                            {
                                existing.Refresh();
                                if (existing.Status != ServiceControllerStatus.Stopped)
                                {
                                    if (existing.Status != ServiceControllerStatus.StopPending) existing.Stop();
                                    existing.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(45));
                                }
                            }
                            if (switched && existing == null) Administration.RemoveRegistration();
                            update.Rollback();
                            if (restart)
                            {
                                existing!.Refresh();
                                if (existing.Status == ServiceControllerStatus.StopPending)
                                    existing.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(45));
                                existing.Refresh();
                                if (existing.Status == ServiceControllerStatus.Stopped) existing.Start();
                                existing.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(45));
                            }
                        }
                        catch (Exception recovery)
                        {
                            throw new IOException($"{failure.Message} Восстановление прежней поставки или службы не завершено. {recovery.Message}", failure);
                        }
                        throw;
                    }
                    return 0;
                }
                store.Initialize(true); admin.Install(); Console.WriteLine("Служба установлена в " + Path.GetDirectoryName(exe) + ". Применение правил выполняется отдельно."); return 0;
            }
            if (command == "apply" && !File.Exists(Deployment.InstalledHost)) throw new InvalidOperationException("Перед применением правил установите службу кнопкой «Установить».");
            if (command is "apply" or "confirm" && File.Exists(Deployment.InstalledHost) && !Path.GetFullPath(exe).Equals(Path.GetFullPath(Deployment.InstalledHost), StringComparison.OrdinalIgnoreCase))
            {
                Console.WriteLine(Native.Run(Deployment.InstalledHost, args.Concat(new[] { "--data", root }), 180000)); return 0;
            }
            if (command == "uninstall") { if (rest.Length != 1 || rest[0] is not ("--restore" or "--keep-trusted")) throw new ArgumentException("Выберите uninstall --restore либо --keep-trusted."); admin.Uninstall(rest[0] == "--restore"); return 0; }
            if (command is "start" or "stop" or "restart")
            {
                if (!ServiceController.GetServices().Any(s => s.ServiceName == Administration.ServiceName)) throw new InvalidOperationException("Служба ещё не установлена. Сначала нажмите «Установить».");
                using var service = new ServiceController(Administration.ServiceName);
                if (command is "stop" or "restart" && service.Status != ServiceControllerStatus.Stopped) { service.Stop(); service.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(45)); }
                if (command is "start" or "restart" && service.Status != ServiceControllerStatus.Running) { service.Start(); service.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(45)); }
                return 0;
            }
            if (command == "cleanup") { engine.Cleanup(); return 0; }
            string? output = null;
            if (command == "clients-export")
            {
                output = Path.GetFullPath(rest[2]);
                string format = Path.GetExtension(output).ToLowerInvariant() switch
                {
                    ".bat" => "bat",
                    ".ps1" => "ps1",
                    ".applescript" => "applescript",
                    ".scpt" => throw new ArgumentException("Сохраните .applescript, затем откройте его в Редакторе скриптов на Mac и сохраните в формате «Скрипт» (.scpt)."),
                    _ => throw new ArgumentException("Выберите .bat, .ps1 или .applescript.")
                };
                rest = [rest[0], rest[1], rest.Length > 3 ? rest[3] : "false", format];
            }
            if (command == "config-save") rest = [File.ReadAllText(rest[0])];
            bool running = ServiceController.GetServices().Any(s => s.ServiceName == Administration.ServiceName && s.Status == ServiceControllerStatus.Running);
            string result;
            if (running) { var reply = await Ipc.Call(command, rest); if (!reply.Ok) throw new InvalidOperationException(reply.Data); result = reply.Data; }
            else result = admin.Dispatch(command, rest, Process.GetCurrentProcess().SessionId);
            if (output != null) { Store.Atomic(output, result, false, Path.GetExtension(output).Equals(".ps1", StringComparison.OrdinalIgnoreCase)); Console.WriteLine("Скрипт сохранён: " + output); }
            else Console.WriteLine(result);
            return 0;
        }
        catch (Exception e) { Console.Error.WriteLine(e.Message); return 1; }
    }
    private const string Help = """
portGate — Windows Server 2016/2019/2022. Запуск администратора.
init | install | uninstall --restore/--keep-trusted
start | stop | restart | status | diagnose | plan | apply | confirm | restore | cleanup
config | config-save FILE.json | events | leases-revoke | lease-revoke ID
clients list
clients create NAME SECONDS [EXPIRY_ISO8601]
clients edit ID NAME [EXPIRY_ISO8601]
clients revoke ID | clients rotate ID
clients export ID SERVER OUTPUT.bat|OUTPUT.ps1|OUTPUT.applescript [true]
run — консольный запуск; service — режим SCM
--data PATH — каталог состояния (по умолчанию %ProgramData%\portgate)
Код 0: успех; 1: ошибка. plan/diagnose не меняют правила.
""";
}
internal sealed class GateService : ServiceBase
{
    private readonly Store store;
    private readonly Engine engine;
    private readonly Administration admin;
    public GateService(Store store, Engine engine, Administration admin) { this.store = store; this.engine = engine; this.admin = admin; ServiceName = Administration.ServiceName; CanStop = true; AutoLog = true; }
    private CancellationTokenSource? cancel;
    private Task? worker;
    protected override void OnStart(string[] args)
    {
        cancel = new();
        // Keep startup work off the SCM callback; failures are written before the recovery exit.
        worker = Task.Run(() => Runtime.Run(store, engine, admin, cancel.Token));
        _ = worker.ContinueWith(t =>
        {
            if (!t.IsFaulted) return;
            try { store.Log("ServiceFailed", t.Exception!.GetBaseException().Message); } catch { }
            Environment.Exit(1);
        }, TaskScheduler.Default);
    }
    protected override void OnStop()
    {
        cancel?.Cancel();
        try { worker?.GetAwaiter().GetResult(); } catch (OperationCanceledException) { }
        cancel?.Dispose();
    }
}
internal static class Runtime
{
    internal static UdpClient BindListener(IPAddress address, int port)
    {
        var listener = new UdpClient(address.AddressFamily);
        try
        {
            if (address.Equals(IPAddress.IPv6Any)) listener.Client.DualMode = true;
            const int sioUdpConnReset = unchecked((int)0x9800000C);
            listener.Client.IOControl(sioUdpConnReset, new byte[sizeof(int)], null);
            listener.Client.Bind(new IPEndPoint(address, port));
            return listener;
        }
        catch
        {
            listener.Dispose();
            throw;
        }
    }

    public static async Task Run(Store store, Engine engine, Administration admin, CancellationToken token)
    {
        engine.Startup();
        var config = store.Config();
        using var listener = BindListener(IPAddress.Parse(config.ListenAddress), config.UdpPort);
        store.TryLog("ServiceStarted", "Слушатель авторизации запущен.");
        using var all = CancellationTokenSource.CreateLinkedTokenSource(token);
        bool healthy = false;
        var maintenance = Task.Run(async () =>
        {
            long previous = Environment.TickCount64; var previousUtc = DateTimeOffset.UtcNow;
            try
            {
                while (!all.IsCancellationRequested)
                {
                    long nowTick = Environment.TickCount64; var nowUtc = DateTimeOffset.UtcNow;
                    if (Math.Abs((nowUtc - previousUtc).TotalMilliseconds - (nowTick - previous)) > 5000) { engine.RevokeAll(); Volatile.Write(ref healthy, false); store.TryLog("ClockChanged", "Временные разрешения отозваны."); }
                    previous = nowTick; previousUtc = nowUtc;
                    engine.Cleanup(sweepOrphans: false, attemptRollback: false);
                    await Task.Delay(TimeSpan.FromSeconds(5), all.Token);
                }
            }
            catch (OperationCanceledException) when (all.IsCancellationRequested) { }
            catch { all.Cancel(); throw; }
        }, CancellationToken.None);
        // Slow policy inspection must not delay expiry cleanup or hold the store mutex.
        var healthMonitor = Task.Run(async () =>
        {
            try
            {
                while (!all.IsCancellationRequested)
                {
                    Volatile.Write(ref healthy, admin.RefreshHealth(all.Token));
                    await Task.Delay(TimeSpan.FromSeconds(30), all.Token);
                }
            }
            catch (OperationCanceledException) when (all.IsCancellationRequested) { }
            catch { Volatile.Write(ref healthy, false); all.Cancel(); throw; }
        }, CancellationToken.None);
        Task RunIpc(bool statusOnly) => Task.Run(async () =>
        {
            try
            {
                while (!all.IsCancellationRequested)
                {
                    using var pipe = Ipc.Create(statusOnly);
                    await pipe.WaitForConnectionAsync(all.Token);
                    using var timeout = CancellationTokenSource.CreateLinkedTokenSource(all.Token);
                    timeout.CancelAfter(TimeSpan.FromSeconds(statusOnly ? 4 : 180));
                    await Ipc.ServeConnection(pipe, request =>
                    {
                        if (statusOnly && request.Command != "status") return new RpcResponse(false, "Канал предназначен для чтения состояния.");
                        if (statusOnly) return new RpcResponse(true, admin.Dispatch("status", [], 0, timeout.Token));
                        var response = new RpcResponse(true, admin.Dispatch(request.Command, request.Args, Ipc.ClientSession(pipe), timeout.Token));
                        if (request.Command == "confirm") Volatile.Write(ref healthy, true);
                        if (request.Command is "apply" or "restore") Volatile.Write(ref healthy, false);
                        return response;
                    }, timeout.Token);
                }
            }
            catch (OperationCanceledException) when (all.IsCancellationRequested) { }
            catch { all.Cancel(); throw; }
        }, CancellationToken.None);
        var ipc = RunIpc(false);
        var statusIpc = RunIpc(true);
        try
        {
            long lastRequestError = -60000;
            while (!all.IsCancellationRequested)
            {
                UdpReceiveResult packet;
                try { packet = await listener.ReceiveAsync(all.Token); }
                catch (SocketException error) when (error.SocketErrorCode is SocketError.ConnectionReset or SocketError.MessageSize)
                {
                    long now = Environment.TickCount64;
                    if (now - lastRequestError >= 60000)
                    {
                        lastRequestError = now;
                        store.TryLog("RequestFailed", "Приём UDP: " + error.SocketErrorCode);
                    }
                    continue;
                }
                if (!Volatile.Read(ref healthy) || packet.Buffer.Length > 1200) continue;
                try
                {
                    string? result = engine.Handle(Encoding.UTF8.GetString(packet.Buffer), packet.RemoteEndPoint.Address, DateTimeOffset.UtcNow);
                    if (result != null) await listener.SendAsync(Encoding.UTF8.GetBytes(result), packet.RemoteEndPoint, all.Token);
                }
                catch (Exception error) when (error is GrantException or SocketException or System.TimeoutException)
                {
                    long now = Environment.TickCount64;
                    if (now - lastRequestError < 60000) continue;
                    lastRequestError = now;
                    store.TryLog("RequestFailed", error.Message);
                }
            }
        }
        catch (OperationCanceledException) when (all.IsCancellationRequested) { }
        finally
        {
            all.Cancel();
            try { await Task.WhenAll(maintenance, ipc, statusIpc, healthMonitor); }
            finally { engine.RevokeAll(); store.TryLog("ServiceStopped", "Временные разрешения отозваны."); }
        }
    }
}
