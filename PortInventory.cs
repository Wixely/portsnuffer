using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

internal static unsafe partial class PortInventory
{
    private const int AddressFamilyIPv4 = (int)AddressFamily.InterNetwork;
    private const int AddressFamilyIPv6 = (int)AddressFamily.InterNetworkV6;
    private const uint NoError = 0;
    private const uint ErrorInsufficientBuffer = 122;

    public static IReadOnlyList<PortProcessInfo> Snapshot()
    {
        var bindingsByPid = new Dictionary<int, HashSet<PortBinding>>();

        AddBindings(bindingsByPid, EnumerateTcpListenersV4());
        AddBindings(bindingsByPid, EnumerateTcpListenersV6());
        AddBindings(bindingsByPid, EnumerateUdpListenersV4());
        AddBindings(bindingsByPid, EnumerateUdpListenersV6());

        return bindingsByPid
            .Select(static entry => BuildProcessInfo(entry.Key, entry.Value))
            .OrderBy(static info => info.Name, StringComparer.OrdinalIgnoreCase)
            .ThenBy(static info => info.ProcessId)
            .ToArray();
    }

    private static void AddBindings(Dictionary<int, HashSet<PortBinding>> bindingsByPid, IEnumerable<PortBinding> bindings)
    {
        foreach (var binding in bindings)
        {
            if (!bindingsByPid.TryGetValue(binding.ProcessId, out var processBindings))
            {
                processBindings = [];
                bindingsByPid[binding.ProcessId] = processBindings;
            }

            processBindings.Add(binding);
        }
    }

    private static PortProcessInfo BuildProcessInfo(int processId, IEnumerable<PortBinding> bindings)
    {
        var sortedBindings = bindings
            .OrderBy(static binding => binding.Protocol)
            .ThenBy(static binding => binding.IsIpv6)
            .ThenBy(static binding => binding.Port)
            .ToArray();

        string name = processId switch
        {
            0 => "Idle",
            4 => "System",
            _ => $"PID {processId}"
        };

        if (processId > 0)
        {
            try
            {
                using var process = Process.GetProcessById(processId);
                name = process.ProcessName;
            }
            catch
            {
            }
        }

        var canTerminate = processId > 4 && processId != Environment.ProcessId;
        return new PortProcessInfo(processId, name, sortedBindings, canTerminate);
    }

    private static IEnumerable<PortBinding> EnumerateTcpListenersV4()
    {
        foreach (var row in ReadRows<MibTcpTableOwnerPid, MibTcpRowOwnerPid>(
                     (IntPtr buffer, ref uint size) => GetExtendedTcpTable(
                         buffer,
                         ref size,
                         order: true,
                         ulAf: AddressFamilyIPv4,
                         tableClass: TcpTableClass.OwnerPidListener,
                         reserved: 0)))
        {
            yield return new PortBinding((int)row.OwningPid, PortProtocol.Tcp, ConvertPort(row.LocalPort), IsIpv6: false);
        }
    }

    private static IEnumerable<PortBinding> EnumerateTcpListenersV6()
    {
        foreach (var row in ReadRows<MibTcp6TableOwnerPid, MibTcp6RowOwnerPid>(
                     (IntPtr buffer, ref uint size) => GetExtendedTcpTable(
                         buffer,
                         ref size,
                         order: true,
                         ulAf: AddressFamilyIPv6,
                         tableClass: TcpTableClass.OwnerPidListener,
                         reserved: 0)))
        {
            yield return new PortBinding((int)row.OwningPid, PortProtocol.Tcp, ConvertPort(row.LocalPort), IsIpv6: true);
        }
    }

    private static IEnumerable<PortBinding> EnumerateUdpListenersV4()
    {
        foreach (var row in ReadRows<MibUdpTableOwnerPid, MibUdpRowOwnerPid>(
                     (IntPtr buffer, ref uint size) => GetExtendedUdpTable(
                         buffer,
                         ref size,
                         order: true,
                         ulAf: AddressFamilyIPv4,
                         tableClass: UdpTableClass.OwnerPid,
                         reserved: 0)))
        {
            yield return new PortBinding((int)row.OwningPid, PortProtocol.Udp, ConvertPort(row.LocalPort), IsIpv6: false);
        }
    }

    private static IEnumerable<PortBinding> EnumerateUdpListenersV6()
    {
        foreach (var row in ReadRows<MibUdp6TableOwnerPid, MibUdp6RowOwnerPid>(
                     (IntPtr buffer, ref uint size) => GetExtendedUdpTable(
                         buffer,
                         ref size,
                         order: true,
                         ulAf: AddressFamilyIPv6,
                         tableClass: UdpTableClass.OwnerPid,
                         reserved: 0)))
        {
            yield return new PortBinding((int)row.OwningPid, PortProtocol.Udp, ConvertPort(row.LocalPort), IsIpv6: true);
        }
    }

    private static IReadOnlyList<TRow> ReadRows<TTable, TRow>(NativeTableReader readTable)
        where TTable : unmanaged
        where TRow : unmanaged
    {
        uint bufferSize = 0;
        var result = readTable(IntPtr.Zero, ref bufferSize);
        if (result != NoError && result != ErrorInsufficientBuffer)
        {
            throw new Win32Exception((int)result);
        }

        var buffer = Marshal.AllocHGlobal((int)bufferSize);
        try
        {
            result = readTable(buffer, ref bufferSize);
            if (result != NoError)
            {
                throw new Win32Exception((int)result);
            }

            var rowCount = Marshal.ReadInt32(buffer);
            var rowSize = Marshal.SizeOf<TRow>();
            var firstRowOffset = Marshal.OffsetOf<TTable>("Table").ToInt32();
            var rows = new TRow[rowCount];

            for (var index = 0; index < rowCount; index++)
            {
                var rowPointer = (byte*)buffer + firstRowOffset + (index * rowSize);
                rows[index] = Unsafe.ReadUnaligned<TRow>(rowPointer);
            }

            return rows;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static int ConvertPort(uint networkOrderPort)
        => (ushort)IPAddress.NetworkToHostOrder((short)(networkOrderPort & 0xFFFF));

    private delegate uint NativeTableReader(IntPtr buffer, ref uint bufferSize);

    [LibraryImport("iphlpapi.dll")]
    private static partial uint GetExtendedTcpTable(
        IntPtr pTcpTable,
        ref uint pdwSize,
        [MarshalAs(UnmanagedType.Bool)] bool order,
        int ulAf,
        TcpTableClass tableClass,
        uint reserved);

    [LibraryImport("iphlpapi.dll")]
    private static partial uint GetExtendedUdpTable(
        IntPtr pUdpTable,
        ref uint pdwSize,
        [MarshalAs(UnmanagedType.Bool)] bool order,
        int ulAf,
        UdpTableClass tableClass,
        uint reserved);

    private enum TcpTableClass
    {
        BasicListener,
        BasicConnections,
        BasicAll,
        OwnerPidListener,
        OwnerPidConnections,
        OwnerPidAll,
        OwnerModuleListener,
        OwnerModuleConnections,
        OwnerModuleAll
    }

    private enum UdpTableClass
    {
        Basic,
        OwnerPid,
        OwnerModule
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcpTableOwnerPid
    {
        public uint NumberOfEntries;
        public MibTcpRowOwnerPid Table;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcpRowOwnerPid
    {
        public uint State;
        public uint LocalAddress;
        public uint LocalPort;
        public uint RemoteAddress;
        public uint RemotePort;
        public uint OwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcp6TableOwnerPid
    {
        public uint NumberOfEntries;
        public MibTcp6RowOwnerPid Table;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcp6RowOwnerPid
    {
        public fixed byte LocalAddress[16];
        public uint LocalScopeId;
        public uint LocalPort;
        public fixed byte RemoteAddress[16];
        public uint RemoteScopeId;
        public uint RemotePort;
        public uint State;
        public uint OwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibUdpTableOwnerPid
    {
        public uint NumberOfEntries;
        public MibUdpRowOwnerPid Table;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibUdpRowOwnerPid
    {
        public uint LocalAddress;
        public uint LocalPort;
        public uint OwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibUdp6TableOwnerPid
    {
        public uint NumberOfEntries;
        public MibUdp6RowOwnerPid Table;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibUdp6RowOwnerPid
    {
        public fixed byte LocalAddress[16];
        public uint LocalScopeId;
        public uint LocalPort;
        public uint OwningPid;
    }
}

internal enum PortProtocol
{
    Tcp,
    Udp
}

internal readonly record struct PortBinding(int ProcessId, PortProtocol Protocol, int Port, bool IsIpv6)
{
    public string DisplayText => $"{(Protocol == PortProtocol.Tcp ? "TCP" : "UDP")}{(IsIpv6 ? "6" : string.Empty)} {Port}";
}

internal sealed record PortProcessInfo(
    int ProcessId,
    string Name,
    IReadOnlyList<PortBinding> PortBindings,
    bool CanTerminate)
{
    public string DisplayName => $"{Name} (PID {ProcessId})";
}
