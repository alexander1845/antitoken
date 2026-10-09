using System.Buffers.Binary;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace TokenVault.Launcher;

// Writes a JKS truststore (trusted-certificate entries only, no private keys) without needing keytool.
// It holds the vault's loopback certificate plus the Windows trusted roots, so ordinary HTTPS used by the
// game and mods (resource packs, skins, mod update checks) keeps working.
public static class JavaTrustStore
{
    public const string Password = "changeit"; // Integrity check only; the store contains public certificates.

    public static byte[] Create(IEnumerable<(string Alias, byte[] Der)> entries, DateTimeOffset created)
    {
        var list = entries.ToList();
        using var body = new MemoryStream();
        Int(body, unchecked((int)0xFEEDFEED)); Int(body, 2); Int(body, list.Count);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var (alias, der) in list)
        {
            if (alias.Length is < 1 or > 200 || alias.Any(ch => ch is < '!' or > '~') || alias != alias.ToLowerInvariant() || !seen.Add(alias))
                throw new ArgumentException("Truststore aliases must be unique lowercase ASCII.");
            Int(body, 2); // trusted certificate entry
            Utf(body, alias);
            Long(body, created.ToUnixTimeMilliseconds());
            Utf(body, "X.509");
            Int(body, der.Length); body.Write(der);
        }
        byte[] data = body.ToArray();
        using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA1);
        sha.AppendData(Encoding.BigEndianUnicode.GetBytes(Password));
        sha.AppendData("Mighty Aphrodite"u8);
        sha.AppendData(data);
        return [.. data, .. sha.GetHashAndReset()];
    }

    [SupportedOSPlatform("windows")]
    public static IEnumerable<(string Alias, byte[] Der)> WindowsRoots()
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var location in new[] { StoreLocation.LocalMachine, StoreLocation.CurrentUser })
        {
            using var store = new X509Store(StoreName.Root, location);
            store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
            foreach (var cert in store.Certificates)
                using (cert)
                    if (cert.NotAfter > DateTime.Now && seen.Add(cert.Thumbprint))
                        yield return ("root-" + cert.Thumbprint.ToLowerInvariant(), cert.RawData);
        }
    }

    private static void Int(Stream s, int value) { Span<byte> b = stackalloc byte[4]; BinaryPrimitives.WriteInt32BigEndian(b, value); s.Write(b); }
    private static void Long(Stream s, long value) { Span<byte> b = stackalloc byte[8]; BinaryPrimitives.WriteInt64BigEndian(b, value); s.Write(b); }
    private static void Utf(Stream s, string value)
    {
        byte[] bytes = Encoding.ASCII.GetBytes(value); // ASCII is identical in Java's modified UTF-8
        Span<byte> length = stackalloc byte[2]; BinaryPrimitives.WriteUInt16BigEndian(length, checked((ushort)bytes.Length));
        s.Write(length); s.Write(bytes);
    }
}
