using System.Net;
using System.Runtime.InteropServices;
using TokenVault.Core;

namespace TokenVault.Vault;

// Finds where to connect the same way the game does: an address without a port is first looked up as a
// "_minecraft._tcp.<host>" SRV record, which many hosted servers use to point at their real machine and port.
public static class ServerResolver
{
    public sealed record Endpoint(string Host, int Port);

    public static async Task<Endpoint> ResolveAsync(ServerEntry server, CancellationToken ct)
    {
        var direct = new Endpoint(server.Host, server.Port);
        if (server.Port != 25565 || IPAddress.TryParse(server.Host, out _) || !OperatingSystem.IsWindows()) return direct;
        // DnsQuery blocks; the system resolver (and its cache) answers like it does for every other program.
        // No answer within 5 seconds: connect directly, as the game does when a lookup fails.
        string name = "_minecraft._tcp." + server.Host;
        var lookup = Task.Run(() => QuerySrv(name), ct);
        try { return await lookup.WaitAsync(TimeSpan.FromSeconds(5), ct) ?? direct; }
        catch (TimeoutException) { return direct; }
    }

    private static Endpoint? QuerySrv(string name)
    {
        if (!OperatingSystem.IsWindows()) return null;
        if (DnsQuery(name, 33 /* SRV */, 0 /* DNS_QUERY_STANDARD */, IntPtr.Zero, out IntPtr list, IntPtr.Zero) != 0) return null;
        try
        {
            Endpoint? best = null;
            int bestPriority = int.MaxValue, bestWeight = -1;
            int p = IntPtr.Size, data = 2 * p + 16; // DNS_RECORD: pNext, pName, wType, wDataLength, Flags, dwTtl, dwReserved, Data
            for (IntPtr record = list; record != IntPtr.Zero; record = Marshal.ReadIntPtr(record))
            {
                if ((ushort)Marshal.ReadInt16(record, 2 * p) != 33) continue;
                // DNS_SRV_DATA: pNameTarget, wPriority, wWeight, wPort
                string? target = Marshal.PtrToStringUni(Marshal.ReadIntPtr(record, data))?.TrimEnd('.');
                int priority = (ushort)Marshal.ReadInt16(record, data + p), weight = (ushort)Marshal.ReadInt16(record, data + p + 2);
                int port = (ushort)Marshal.ReadInt16(record, data + p + 4);
                if (string.IsNullOrEmpty(target) || target.Length > 253 || port == 0 || target.Any(ch => char.IsControl(ch) || char.IsWhiteSpace(ch))) continue;
                if (priority < bestPriority || (priority == bestPriority && weight > bestWeight))
                    (best, bestPriority, bestWeight) = (new Endpoint(target, port), priority, weight);
            }
            return best;
        }
        finally { DnsRecordListFree(list, 1 /* DnsFreeRecordList */); }
    }

    [DllImport("dnsapi.dll", CharSet = CharSet.Unicode, EntryPoint = "DnsQuery_W")]
    private static extern int DnsQuery(string name, ushort type, uint options, IntPtr extra, out IntPtr results, IntPtr reserved);
    [DllImport("dnsapi.dll")] private static extern void DnsRecordListFree(IntPtr list, int freeType);
}
