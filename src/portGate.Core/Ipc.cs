using Microsoft.Win32.SafeHandles;
using System.ComponentModel;
using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Text;

namespace portGate.Core;
public sealed record RpcRequest(string Command, string[] Args);
public sealed record RpcResponse(bool Ok, string Data);
public static class Ipc
{
    public const string PipeName = "KnockGate.v1";
    public const int MaxMessageBytes = 262144;
    [StructLayout(LayoutKind.Sequential)] private struct Security { public int Length; public IntPtr Descriptor; public int Inherit; }
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string descriptor, int version, out IntPtr value, out uint size);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern SafePipeHandle CreateNamedPipeW(string name, uint mode, uint pipeMode, uint instances, uint outSize, uint inSize, uint timeout, ref Security security);
    [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr memory);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool GetNamedPipeClientProcessId(SafePipeHandle pipe, out uint processId);
    private const string StatusPipeName = PipeName + ".status";
    public static NamedPipeServerStream Create(bool statusOnly = false)
    {
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW("D:P(A;;GA;;;SY)(A;;GA;;;BA)", 1, out var descriptor, out _)) throw new Win32Exception();
        try
        {
            var security = new Security { Length = Marshal.SizeOf<Security>(), Descriptor = descriptor };
            // Reject remote clients; first pipe instance blocks name squatting.
            var handle = CreateNamedPipeW(@"\\.\pipe\" + (statusOnly ? StatusPipeName : PipeName), 0x40080003, 8, 1, 65536, 65536, 0, ref security);
            if (handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
            return new NamedPipeServerStream(PipeDirection.InOut, true, false, handle);
        }
        finally { LocalFree(descriptor); }
    }
    public static int ClientSession(NamedPipeServerStream pipe)
    {
        if (!GetNamedPipeClientProcessId(pipe.SafePipeHandle, out uint id)) throw new Win32Exception();
        using var process = Process.GetProcessById(checked((int)id)); return process.SessionId;
    }
    public static async Task<string> Read(Stream stream, CancellationToken token)
    {
        byte[] length = new byte[4]; await stream.ReadExactlyAsync(length, token);
        int count = System.Buffers.Binary.BinaryPrimitives.ReadInt32LittleEndian(length);
        if (count is < 1 or > MaxMessageBytes) throw new InvalidDataException("Недопустимый размер IPC.");
        byte[] bytes = new byte[count]; await stream.ReadExactlyAsync(bytes, token); return Encoding.UTF8.GetString(bytes);
    }
    public static async Task Write(Stream stream, string text, CancellationToken token)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(text); if (bytes.Length > MaxMessageBytes) throw new InvalidDataException("Слишком большой ответ IPC.");
        byte[] length = new byte[4]; System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian(length, bytes.Length);
        await stream.WriteAsync(length, token); await stream.WriteAsync(bytes, token); await stream.FlushAsync(token);
    }
    public static async Task<RpcResponse> Call(string command, params string[] args)
    {
        bool statusOnly = command == "status";
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(statusOnly ? 4 : 180));
        using var pipe = new NamedPipeClientStream(".", statusOnly ? StatusPipeName : PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        await pipe.ConnectAsync(timeout.Token);
        await Write(pipe, Json.Write(new RpcRequest(command, args)), timeout.Token);
        return Json.Read<RpcResponse>(await Read(pipe, timeout.Token));
    }
    public static async Task ServeConnection(Stream stream, Func<RpcRequest, RpcResponse> dispatch, CancellationToken token)
    {
        try
        {
            var request = Json.Read<RpcRequest>(await Read(stream, token));
            if (string.IsNullOrEmpty(request.Command) || request.Args == null || request.Args.Any(a => a == null)) throw new InvalidDataException("Некорректный запрос IPC.");
            RpcResponse response;
            try { response = dispatch(request); }
            catch (OperationCanceledException) when (token.IsCancellationRequested) { throw; }
            catch (Exception e) { response = new(false, e.Message); }
            string text = Json.Write(response);
            if (Encoding.UTF8.GetByteCount(text) > MaxMessageBytes) text = Json.Write(new RpcResponse(false, "Ответ превышает допустимый размер IPC. Уменьшите объём запроса."));
            await Write(stream, text, token);
        }
        catch (Exception e) when (e is InvalidDataException or IOException or OperationCanceledException or System.Text.Json.JsonException) { /* Only this connection is rejected. */ }
    }
}
