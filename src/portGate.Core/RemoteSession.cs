using System.Runtime.InteropServices;

namespace portGate.Core;
public static class RemoteSession
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct Info
    {
        public int State; public uint SessionId;
        public uint IncomingBytes, OutgoingBytes, IncomingFrames, OutgoingFrames, IncomingCompressedBytes, OutgoingCompressedBytes;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string Station;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 17)] public string Domain;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 21)] public string User;
        public long ConnectTime, DisconnectTime, LastInputTime, LogonTime, CurrentTime;
    }
    [DllImport("wtsapi32.dll", CharSet = CharSet.Unicode)] private static extern bool WTSQuerySessionInformationW(IntPtr server, int session, int kind, out IntPtr buffer, out int bytes);
    [DllImport("wtsapi32.dll")] private static extern void WTSFreeMemory(IntPtr buffer);
    public static bool IsNew(int session, int original, DateTimeOffset started)
    {
        if (session == 0 || session == original) return false;
        if (!WTSQuerySessionInformationW(IntPtr.Zero, session, 16, out var protocol, out int size)) return false;
        try { if (size < 2 || Marshal.ReadInt16(protocol) != 2) return false; } finally { WTSFreeMemory(protocol); }
        if (!WTSQuerySessionInformationW(IntPtr.Zero, session, 24, out var data, out size)) return false;
        try
        {
            if (size < Marshal.SizeOf<Info>()) return false;
            var info = Marshal.PtrToStructure<Info>(data);
            return info.State == 0 && DateTimeOffset.FromFileTime(info.ConnectTime) >= started;
        }
        finally { WTSFreeMemory(data); }
    }
}
