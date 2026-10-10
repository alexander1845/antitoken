using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace TokenVault.Launcher;

// Which process opened a loopback TCP connection. Windows lists both ends of a loopback connection in its TCP table;
// the row whose local end is the client's address and whose remote end is our listener belongs to the client.
[SupportedOSPlatform("windows")]
public static class LoopbackPeers
{
    public static int? OwnerOf(IPEndPoint client, IPEndPoint server)
    {
        if (client.AddressFamily != AddressFamily.InterNetwork || server.AddressFamily != AddressFamily.InterNetwork) return null;
        uint clientAddress = BitConverter.ToUInt32(client.Address.GetAddressBytes()), serverAddress = BitConverter.ToUInt32(server.Address.GetAddressBytes());
        int size = 0;
        _ = GetExtendedTcpTable(IntPtr.Zero, ref size, false, 2 /* AF_INET */, 5 /* TCP_TABLE_OWNER_PID_ALL */, 0);
        for (int attempt = 0; attempt < 4; attempt++)
        {
            size += 4096; // the table can grow between the two calls
            IntPtr table = Marshal.AllocHGlobal(size);
            try
            {
                uint error = GetExtendedTcpTable(table, ref size, false, 2, 5, 0);
                if (error == 122 /* ERROR_INSUFFICIENT_BUFFER */) continue;
                if (error != 0) return null;
                int count = Marshal.ReadInt32(table);
                // MIB_TCPROW_OWNER_PID: state, localAddr, localPort, remoteAddr, remotePort, owningPid (6 DWORDs).
                for (int i = 0; i < count; i++)
                {
                    IntPtr row = table + 4 + i * 24;
                    if ((uint)Marshal.ReadInt32(row, 4) == clientAddress && Port(Marshal.ReadInt32(row, 8)) == client.Port &&
                        (uint)Marshal.ReadInt32(row, 12) == serverAddress && Port(Marshal.ReadInt32(row, 16)) == server.Port)
                        return Marshal.ReadInt32(row, 20);
                }
                return null;
            }
            finally { Marshal.FreeHGlobal(table); }
        }
        return null;
    }

    // Ports are stored in network byte order in the low 16 bits.
    private static int Port(int raw) => ((raw & 0xFF) << 8) | ((raw >> 8) & 0xFF);

    [DllImport("iphlpapi.dll")]
    private static extern uint GetExtendedTcpTable(IntPtr table, ref int size, bool sort, int family, int tableClass, uint reserved);
}
