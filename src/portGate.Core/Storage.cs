using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Security.AccessControl;
using System.Text;

namespace portGate.Core;

public sealed class Store
{
    public string Root { get; }
    public string ConfigPath => Path.Combine(Root, "config.json");
    public string StatePath => Path.Combine(Root, "state.json");
    public Store(string root) => Root = Path.GetFullPath(root);
    public IDisposable Lock() => Acquire("store", 20);
    public IDisposable LockPolicy() => Acquire("policy", 20);
    public IDisposable LockDeployment() => Acquire("deployment", 20);
    private IDisposable Acquire(string purpose, int seconds)
    {
        var name = "Global\\KnockGate-" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(Root.ToUpperInvariant())))[..20];
        if (purpose != "store") name += "-" + purpose;
        var mutex = Native.SecureMutex(name);
        try { if (!mutex.WaitOne(TimeSpan.FromSeconds(seconds))) throw new TimeoutException("portGate занят другой операцией. Повторите попытку."); }
        catch (AbandonedMutexException) { }
        catch { mutex.Dispose(); throw; }
        return new Unlock(mutex);
    }
    private sealed class Unlock(Mutex mutex) : IDisposable { public void Dispose() { mutex.ReleaseMutex(); mutex.Dispose(); } }
    public void Initialize(bool secure)
    {
        Directory.CreateDirectory(Root);
        if (secure)
        {
            RequireAdmin();
            SecureDirectory(Root);
        }
        using var guard = Lock();
        if (!File.Exists(ConfigPath)) Atomic(ConfigPath, Json.Write(new Config()), true);
        if (!File.Exists(StatePath)) Save(new State());
    }
    private static void SecureDirectory(string path)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) throw new IOException("Хранилище не может содержать ссылки или junction.");
        var admin = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var acl = new DirectorySecurity(); acl.SetAccessRuleProtection(true, false); acl.SetOwner(admin);
        foreach (var sid in new[] { admin, system }) acl.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        new DirectoryInfo(path).SetAccessControl(acl);
        foreach (string entry in Directory.EnumerateFileSystemEntries(path))
        {
            var attributes = File.GetAttributes(entry);
            if ((attributes & FileAttributes.ReparsePoint) != 0) throw new IOException("Хранилище не может содержать ссылки или junction.");
            if ((attributes & FileAttributes.Directory) != 0) { SecureDirectory(entry); continue; }
            var fileAcl = new FileSecurity(); fileAcl.SetAccessRuleProtection(true, false); fileAcl.SetOwner(admin);
            foreach (var sid in new[] { admin, system }) fileAcl.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl, AccessControlType.Allow));
            new FileInfo(entry).SetAccessControl(fileAcl);
        }
    }
    public Config Config() { var config = Json.Read<Config>(File.ReadAllText(ConfigPath)); config.Validate(allowLegacyUnrestrictedRdp: true); return config; }
    public void SaveConfig(Config config) { config.Validate(); Atomic(ConfigPath, Json.Write(config), true); }
    public State Load()
    {
        var envelope = Json.Read<Envelope>(File.ReadAllText(StatePath));
        var bytes = Convert.FromBase64String(envelope.Data);
        if (Convert.ToHexString(SHA256.HashData(bytes)) != envelope.Sha256) throw new InvalidDataException("Повреждено хранилище состояния. Новые допуски запрещены.");
        var state = Json.Read<State>(Encoding.UTF8.GetString(bytes));
        if (state.SchemaVersion != 1) throw new InvalidDataException("Неизвестная версия состояния.");
        return state;
    }
    public void Save(State state)
    {
        var bytes = Encoding.UTF8.GetBytes(Json.Write(state));
        Atomic(StatePath, Json.Write(new Envelope(Convert.ToBase64String(bytes), Convert.ToHexString(SHA256.HashData(bytes)))), false);
    }
    private sealed record Envelope(string Data, string Sha256);
    public static void Atomic(string path, string data, bool backup, bool utf8Bom = false)
    {
        string temp = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
            { if (utf8Bom) stream.Write(new byte[] { 0xef, 0xbb, 0xbf }); byte[] bytes = Encoding.UTF8.GetBytes(data); stream.Write(bytes); stream.Flush(true); }
            if (File.Exists(path)) File.Replace(temp, path, backup ? path + ".bak" : null);
            else File.Move(temp, path);
        }
        finally { if (File.Exists(temp)) File.Delete(temp); }
    }
    public void Log(string kind, string detail)
    {
        using var guard = Acquire("journal", 3);
        string path = Path.Combine(Root, "events.jsonl");
        if (File.Exists(path) && new FileInfo(path).Length > 2_000_000)
        {
            for (int i = 3; i >= 1; i--) { string source = path + "." + i; if (File.Exists(source)) File.Move(source, path + "." + (i + 1), true); }
            File.Move(path, path + ".1", true);
        }
        File.AppendAllText(path, System.Text.Json.JsonSerializer.Serialize(new { time = DateTimeOffset.UtcNow, kind, detail }) + "\n");
    }
    public void TryLog(string kind, string detail)
    {
        try { Log(kind, detail); }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or Win32Exception or TimeoutException)
        {
            Trace.TraceWarning("portGate: журнал недоступен ({0})", error.GetType().Name);
        }
    }
    public static void RequireAdmin()
    {
        using var identity = WindowsIdentity.GetCurrent();
        if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator) && identity.User?.Value != "S-1-5-18") throw new UnauthorizedAccessException("Требуются права администратора.");
    }
}
public static class Native
{
    [StructLayout(LayoutKind.Sequential)] private struct Security { public int Length; public IntPtr Descriptor; public int Inherit; }
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string descriptor, int version, out IntPtr value, out uint size);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern Microsoft.Win32.SafeHandles.SafeWaitHandle CreateMutexW(ref Security security, bool owner, string name);
    public static Mutex SecureMutex(string name)
    {
        // Administrators and SYSTEM can synchronize across CLI, service and scheduled tasks.
        // The current user is additionally allowed in tests with an isolated data directory.
        string sid = WindowsIdentity.GetCurrent().User?.Value ?? "S-1-5-18";
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW($"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;{sid})", 1, out var descriptor, out _)) throw new Win32Exception();
        try
        {
            var security = new Security { Length = Marshal.SizeOf<Security>(), Descriptor = descriptor };
            var handle = CreateMutexW(ref security, false, name);
            if (handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
            var result = new Mutex(); result.SafeWaitHandle = handle; return result;
        }
        finally { LocalFree(descriptor); }
    }
    [StructLayout(LayoutKind.Sequential)] private struct Blob { public int Length; public IntPtr Data; }
    [DllImport("crypt32.dll", SetLastError = true)] private static extern bool CryptProtectData(ref Blob input, string? description, IntPtr entropy, IntPtr reserved, IntPtr prompt, int flags, out Blob output);
    [DllImport("crypt32.dll", SetLastError = true)] private static extern bool CryptUnprotectData(ref Blob input, IntPtr description, IntPtr entropy, IntPtr reserved, IntPtr prompt, int flags, out Blob output);
    [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr memory);
    [DllImport("kernel32.dll")] private static extern uint GetOEMCP();
    public static string Protect(byte[] key) => Convert.ToBase64String(Crypt(key, true));
    public static byte[] Unprotect(string key) => Crypt(Convert.FromBase64String(key), false);
    private static byte[] Crypt(byte[] bytes, bool protect)
    {
        var input = new Blob { Length = bytes.Length, Data = Marshal.AllocHGlobal(bytes.Length) };
        try
        {
            Marshal.Copy(bytes, 0, input.Data, bytes.Length);
            Blob output;
            bool ok = protect ? CryptProtectData(ref input, null, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 5, out output) : CryptUnprotectData(ref input, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 1, out output);
            if (!ok) throw new Win32Exception(Marshal.GetLastWin32Error());
            try { byte[] result = new byte[output.Length]; Marshal.Copy(output.Data, result, 0, result.Length); return result; }
            finally { LocalFree(output.Data); }
        }
        finally { Marshal.FreeHGlobal(input.Data); }
    }
    public static string Run(string file, IEnumerable<string> args, int timeout = 30000, Encoding? outputEncoding = null, CancellationToken cancellationToken = default)
    {
        var info = new ProcessStartInfo(file) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        if (outputEncoding == null && new[] { "sc.exe", "schtasks.exe", "icacls.exe" }.Contains(Path.GetFileName(file), StringComparer.OrdinalIgnoreCase))
        { Encoding.RegisterProvider(CodePagesEncodingProvider.Instance); outputEncoding = Encoding.GetEncoding((int)GetOEMCP()); }
        info.StandardOutputEncoding = outputEncoding ?? Encoding.UTF8;
        info.StandardErrorEncoding = outputEncoding ?? Encoding.UTF8;
        foreach (string arg in args) info.ArgumentList.Add(arg);
        cancellationToken.ThrowIfCancellationRequested();
        using var process = Process.Start(info) ?? throw new IOException("Не удалось запустить процесс.");
        var stdout = process.StandardOutput.ReadToEndAsync(); var stderr = process.StandardError.ReadToEndAsync();
        var elapsed = Stopwatch.StartNew();
        try
        {
            while (!process.WaitForExit(100))
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (elapsed.ElapsedMilliseconds >= timeout) throw new TimeoutException("Превышено время операции.");
            }
            cancellationToken.ThrowIfCancellationRequested();
        }
        catch
        {
            if (!process.HasExited) { process.Kill(true); process.WaitForExit(5000); }
            throw;
        }
        Task.WaitAll(stdout, stderr);
        if (process.ExitCode != 0) throw new IOException($"{Path.GetFileName(file)}: {stderr.Result} {stdout.Result}");
        return stdout.Result;
    }
    public static string PowerShell(string script, int timeout = 30000, CancellationToken cancellationToken = default) => Run("powershell.exe", ["-NoProfile", "-NonInteractive", "-EncodedCommand", Convert.ToBase64String(Encoding.Unicode.GetBytes("$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false); " + script))], timeout, cancellationToken: cancellationToken);
}
