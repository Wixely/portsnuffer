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
    private const uint TcpStateListen = 2;
    private const uint TcpStateDeleteTcb = 12;

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

    public static IReadOnlyList<TcpConnectionInfo> ConnectionsSnapshot()
    {
        var listenerPortsByPid = Snapshot()
            .ToDictionary(
                static process => process.ProcessId,
                static process => process.PortBindings
                    .Where(static binding => binding.Protocol == PortProtocol.Tcp)
                    .Select(static binding => binding.Port)
                    .ToHashSet());

        return EnumerateTcpConnectionsV4()
            .Concat(EnumerateTcpConnectionsV6())
            .Select(connection => connection with
            {
                ProcessName = GetProcessName(connection.ProcessId),
                Direction = IsLikelyInbound(connection, listenerPortsByPid) ? ConnectionDirection.Inbound : ConnectionDirection.Outbound
            })
            .OrderBy(static connection => connection.ProcessName, StringComparer.OrdinalIgnoreCase)
            .ThenBy(static connection => connection.ProcessId)
            .ThenBy(static connection => connection.LocalPort)
            .ThenBy(static connection => connection.RemoteAddress.ToString(), StringComparer.Ordinal)
            .ThenBy(static connection => connection.RemotePort)
            .ToArray();
    }

    public static void CloseConnection(TcpConnectionInfo connection)
    {
        if (!connection.CanClose)
        {
            throw new NotSupportedException("Only IPv4 TCP connections can be closed directly.");
        }

        var row = new MibTcpRow
        {
            State = TcpStateDeleteTcb,
            LocalAddress = connection.RawLocalAddress,
            LocalPort = connection.RawLocalPort,
            RemoteAddress = connection.RawRemoteAddress,
            RemotePort = connection.RawRemotePort
        };

        var result = SetTcpEntry(ref row);
        if (result != NoError)
        {
            throw new Win32Exception((int)result);
        }
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
            .ThenBy(static binding => binding.LocalAddress.ToString(), StringComparer.Ordinal)
            .ThenBy(static binding => binding.Port)
            .ToArray();

        var name = GetProcessName(processId);

        var canTerminate = processId > 4 && processId != Environment.ProcessId;
        return new PortProcessInfo(processId, name, sortedBindings, canTerminate);
    }

    private static string GetProcessName(int processId)
    {
        var name = processId switch
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

        return name;
    }

    private static IEnumerable<PortBinding> EnumerateTcpListenersV4()
    {
        var bindings = new List<PortBinding>();
        foreach (var row in ReadRows<MibTcpTableOwnerPid, MibTcpRowOwnerPid>(
                     (IntPtr buffer, ref uint size) => GetExtendedTcpTable(
                         buffer,
                         ref size,
                         order: true,
                         ulAf: AddressFamilyIPv4,
                         tableClass: TcpTableClass.OwnerPidListener,
                         reserved: 0)))
        {
            bindings.Add(new PortBinding(
                (int)row.OwningPid,
                PortProtocol.Tcp,
                ConvertPort(row.LocalPort),
                IsIpv6: false,
                LocalAddress: ConvertIPv4Address(row.LocalAddress)));
        }

        return bindings;
    }

    private static IEnumerable<PortBinding> EnumerateTcpListenersV6()
    {
        var bindings = new List<PortBinding>();
        foreach (var row in ReadRows<MibTcp6TableOwnerPid, MibTcp6RowOwnerPid>(
                     (IntPtr buffer, ref uint size) => GetExtendedTcpTable(
                         buffer,
                         ref size,
                         order: true,
                         ulAf: AddressFamilyIPv6,
                         tableClass: TcpTableClass.OwnerPidListener,
                         reserved: 0)))
        {
            bindings.Add(new PortBinding(
                (int)row.OwningPid,
                PortProtocol.Tcp,
                ConvertPort(row.LocalPort),
                IsIpv6: true,
                LocalAddress: ConvertIPv6Address(row.LocalAddress, row.LocalScopeId)));
        }

        return bindings;
    }

    private static IEnumerable<PortBinding> EnumerateUdpListenersV4()
    {
        var bindings = new List<PortBinding>();
        foreach (var row in ReadRows<MibUdpTableOwnerPid, MibUdpRowOwnerPid>(
                     (IntPtr buffer, ref uint size) => GetExtendedUdpTable(
                         buffer,
                         ref size,
                         order: true,
                         ulAf: AddressFamilyIPv4,
                         tableClass: UdpTableClass.OwnerPid,
                         reserved: 0)))
        {
            bindings.Add(new PortBinding(
                (int)row.OwningPid,
                PortProtocol.Udp,
                ConvertPort(row.LocalPort),
                IsIpv6: false,
                LocalAddress: ConvertIPv4Address(row.LocalAddress)));
        }

        return bindings;
    }

    private static IEnumerable<PortBinding> EnumerateUdpListenersV6()
    {
        var bindings = new List<PortBinding>();
        foreach (var row in ReadRows<MibUdp6TableOwnerPid, MibUdp6RowOwnerPid>(
                     (IntPtr buffer, ref uint size) => GetExtendedUdpTable(
                         buffer,
                         ref size,
                         order: true,
                         ulAf: AddressFamilyIPv6,
                         tableClass: UdpTableClass.OwnerPid,
                         reserved: 0)))
        {
            bindings.Add(new PortBinding(
                (int)row.OwningPid,
                PortProtocol.Udp,
                ConvertPort(row.LocalPort),
                IsIpv6: true,
                LocalAddress: ConvertIPv6Address(row.LocalAddress, row.LocalScopeId)));
        }

        return bindings;
    }

    private static IEnumerable<TcpConnectionInfo> EnumerateTcpConnectionsV4()
    {
        var connections = new List<TcpConnectionInfo>();
        foreach (var row in ReadRows<MibTcpTableOwnerPid, MibTcpRowOwnerPid>(
                     (IntPtr buffer, ref uint size) => GetExtendedTcpTable(
                         buffer,
                         ref size,
                         order: true,
                         ulAf: AddressFamilyIPv4,
                         tableClass: TcpTableClass.OwnerPidAll,
                         reserved: 0)))
        {
            if (row.State == TcpStateListen)
            {
                continue;
            }

            connections.Add(new TcpConnectionInfo(
                ProcessId: (int)row.OwningPid,
                ProcessName: string.Empty,
                Direction: ConnectionDirection.Outbound,
                State: GetTcpStateName(row.State),
                IsIpv6: false,
                LocalAddress: ConvertIPv4Address(row.LocalAddress),
                LocalPort: ConvertPort(row.LocalPort),
                RemoteAddress: ConvertIPv4Address(row.RemoteAddress),
                RemotePort: ConvertPort(row.RemotePort),
                CanClose: true,
                CanTerminate: CanTerminateProcess((int)row.OwningPid),
                RawLocalAddress: row.LocalAddress,
                RawLocalPort: row.LocalPort,
                RawRemoteAddress: row.RemoteAddress,
                RawRemotePort: row.RemotePort));
        }

        return connections;
    }

    private static IEnumerable<TcpConnectionInfo> EnumerateTcpConnectionsV6()
    {
        var connections = new List<TcpConnectionInfo>();
        foreach (var row in ReadRows<MibTcp6TableOwnerPid, MibTcp6RowOwnerPid>(
                     (IntPtr buffer, ref uint size) => GetExtendedTcpTable(
                         buffer,
                         ref size,
                         order: true,
                         ulAf: AddressFamilyIPv6,
                         tableClass: TcpTableClass.OwnerPidAll,
                         reserved: 0)))
        {
            if (row.State == TcpStateListen)
            {
                continue;
            }

            connections.Add(new TcpConnectionInfo(
                ProcessId: (int)row.OwningPid,
                ProcessName: string.Empty,
                Direction: ConnectionDirection.Outbound,
                State: GetTcpStateName(row.State),
                IsIpv6: true,
                LocalAddress: ConvertIPv6Address(row.LocalAddress, row.LocalScopeId),
                LocalPort: ConvertPort(row.LocalPort),
                RemoteAddress: ConvertIPv6Address(row.RemoteAddress, row.RemoteScopeId),
                RemotePort: ConvertPort(row.RemotePort),
                CanClose: false,
                CanTerminate: CanTerminateProcess((int)row.OwningPid),
                RawLocalAddress: 0,
                RawLocalPort: 0,
                RawRemoteAddress: 0,
                RawRemotePort: 0));
        }

        return connections;
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

    private static IPAddress ConvertIPv4Address(uint address)
        => new(BitConverter.GetBytes(address));

    private static IPAddress ConvertIPv6Address(byte* address, uint scopeId)
    {
        var bytes = new byte[16];
        for (var index = 0; index < bytes.Length; index++)
        {
            bytes[index] = address[index];
        }

        return scopeId == 0
            ? new IPAddress(bytes)
            : new IPAddress(bytes, scopeId);
    }

    private static bool CanTerminateProcess(int processId)
        => processId > 4 && processId != Environment.ProcessId;

    private static bool IsLikelyInbound(
        TcpConnectionInfo connection,
        IReadOnlyDictionary<int, HashSet<int>> listenerPortsByPid)
        => listenerPortsByPid.TryGetValue(connection.ProcessId, out var listenerPorts)
            && listenerPorts.Contains(connection.LocalPort);

    private static string GetTcpStateName(uint state)
        => state switch
        {
            1 => "Closed",
            2 => "Listen",
            3 => "Syn sent",
            4 => "Syn received",
            5 => "Established",
            6 => "Fin wait 1",
            7 => "Fin wait 2",
            8 => "Close wait",
            9 => "Closing",
            10 => "Last ack",
            11 => "Time wait",
            12 => "Delete TCB",
            _ => $"State {state}"
        };

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

    [LibraryImport("iphlpapi.dll")]
    private static partial uint SetTcpEntry(ref MibTcpRow tcpRow);

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
    private struct MibTcpRow
    {
        public uint State;
        public uint LocalAddress;
        public uint LocalPort;
        public uint RemoteAddress;
        public uint RemotePort;
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

internal enum ConnectionDirection
{
    Inbound,
    Outbound
}

internal readonly record struct PortBinding(int ProcessId, PortProtocol Protocol, int Port, bool IsIpv6, IPAddress LocalAddress)
{
    public string DisplayAddress => IsIpv6 ? $"[{LocalAddress}]" : LocalAddress.ToString();

    public string DisplayEndpoint => $"{DisplayAddress}:{Port}";

    public string DisplayText => $"{(Protocol == PortProtocol.Tcp ? "TCP" : "UDP")}{(IsIpv6 ? "6" : string.Empty)} {DisplayEndpoint}";
}

internal sealed record PortProcessInfo(
    int ProcessId,
    string Name,
    IReadOnlyList<PortBinding> PortBindings,
    bool CanTerminate)
{
    public string DisplayName => $"{Name} (PID {ProcessId})";
}

internal sealed record TcpConnectionInfo(
    int ProcessId,
    string ProcessName,
    ConnectionDirection Direction,
    string State,
    bool IsIpv6,
    IPAddress LocalAddress,
    int LocalPort,
    IPAddress RemoteAddress,
    int RemotePort,
    bool CanClose,
    bool CanTerminate,
    uint RawLocalAddress,
    uint RawLocalPort,
    uint RawRemoteAddress,
    uint RawRemotePort)
{
    public string DisplayName => $"{ProcessName} (PID {ProcessId})";

    public string LocalDisplayAddress => FormatAddress(LocalAddress, IsIpv6);

    public string RemoteDisplayAddress => FormatAddress(RemoteAddress, IsIpv6);

    public string LocalEndpoint => $"{LocalDisplayAddress}:{LocalPort}";

    public string RemoteEndpoint => $"{RemoteDisplayAddress}:{RemotePort}";

    private static string FormatAddress(IPAddress address, bool isIpv6)
        => isIpv6 ? $"[{address}]" : address.ToString();
}
