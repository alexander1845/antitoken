using System.Buffers.Binary;
using TokenVault.Core;

namespace TokenVault.Launcher;

// Writes the game's multiplayer list (uncompressed NBT) so every server added in Token Vault appears in-game,
// pointing at that server's local broker. Servers added inside the game connect directly and cannot sign in.
public static class ServersFile
{
    public static byte[] Create(IEnumerable<LocalServer> servers)
    {
        var list = servers.ToList();
        using var nbt = new MemoryStream();
        nbt.WriteByte(10); Name(nbt, "");                // root compound
        nbt.WriteByte(9); Name(nbt, "servers");          // list of compounds
        nbt.WriteByte(10); Int(nbt, list.Count);
        foreach (var server in list)
        {
            nbt.WriteByte(8); Name(nbt, "name"); Name(nbt, server.Name);
            nbt.WriteByte(8); Name(nbt, "ip"); Name(nbt, $"127.0.0.1:{server.Port}");
            nbt.WriteByte(0);
        }
        nbt.WriteByte(0);
        return nbt.ToArray();
    }

    // The folder may be sandbox-writable, so whatever is at this path (possibly a planted link) is removed first
    // and a brand-new file is created; the write can never land outside the folder.
    public static void Write(string path, IEnumerable<LocalServer> servers)
    {
        byte[] data = Create(servers);
        File.Delete(path);
        using var file = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        file.Write(data);
    }

    private static void Int(Stream s, int value) { Span<byte> b = stackalloc byte[4]; BinaryPrimitives.WriteInt32BigEndian(b, value); s.Write(b); }

    // NBT strings: unsigned 16-bit length + Java "modified UTF-8".
    private static void Name(Stream s, string value)
    {
        using var bytes = new MemoryStream();
        foreach (char ch in value)
        {
            if (ch is >= '\u0001' and <= '\u007f') bytes.WriteByte((byte)ch);
            else if (ch <= '߿') { bytes.WriteByte((byte)(0xC0 | (ch >> 6))); bytes.WriteByte((byte)(0x80 | (ch & 0x3F))); }
            else
            {
                bytes.WriteByte((byte)(0xE0 | (ch >> 12)));
                bytes.WriteByte((byte)(0x80 | ((ch >> 6) & 0x3F)));
                bytes.WriteByte((byte)(0x80 | (ch & 0x3F)));
            }
        }
        Span<byte> length = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(length, checked((ushort)bytes.Length));
        s.Write(length); bytes.WriteTo(s);
    }
}
