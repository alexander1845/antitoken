using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;

namespace TokenVault.Core;

public static class PacketIO
{
    public const int MaxPacket = 2 * 1024 * 1024;

    public static int ReadVarInt(ReadOnlySpan<byte> data, ref int offset)
    {
        uint value = 0;
        for (int i = 0; i < 5; i++)
        {
            if (offset >= data.Length) throw new InvalidDataException("Truncated VarInt.");
            byte b = data[offset++];
            if (i == 4 && (b & 0xf0) != 0) throw new InvalidDataException("VarInt overflow.");
            value |= (uint)(b & 127) << (7 * i);
            if ((b & 128) == 0) return unchecked((int)value);
        }
        throw new InvalidDataException("Invalid VarInt.");
    }

    public static void WriteVarInt(Stream stream, int value)
    {
        uint v = unchecked((uint)value);
        do { byte b = (byte)(v & 127); v >>= 7; stream.WriteByte((byte)(b | (v != 0 ? 128 : 0))); } while (v != 0);
    }

    public static string ReadString(byte[] data, ref int offset, int maxChars = 32767)
    {
        byte[] bytes = ReadBytes(data, ref offset, checked(maxChars * 4));
        string value = new UTF8Encoding(false, true).GetString(bytes);
        if (value.Length > maxChars) throw new InvalidDataException("String too long.");
        return value;
    }

    public static byte[] ReadBytes(byte[] data, ref int offset, int maxLength)
    {
        int length = ReadVarInt(data, ref offset);
        if (length < 0 || length > maxLength || length > data.Length - offset)
            throw new InvalidDataException("Invalid byte array length.");
        var bytes = data.AsSpan(offset, length).ToArray();
        offset += length;
        return bytes;
    }

    public static void WriteString(Stream stream, string text) => WriteBytes(stream, Encoding.UTF8.GetBytes(text));
    public static void WriteBytes(Stream stream, byte[] bytes) { WriteVarInt(stream, bytes.Length); stream.Write(bytes); }
    public static void RequireEnd(byte[] packet, int offset)
    { if (packet.Length != offset) throw new InvalidDataException("Unexpected packet fields."); }

    public static byte[] Packet(int id, Action<MemoryStream>? fields = null)
    {
        using var stream = new MemoryStream();
        WriteVarInt(stream, id); fields?.Invoke(stream); return stream.ToArray();
    }

    public static async Task<byte[]> ReadAsync(Stream stream, int compression, CancellationToken ct)
    {
        byte[] prefix = new byte[5];
        int length = 0;
        for (int i = 0; i < 5; i++)
        {
            await stream.ReadExactlyAsync(prefix.AsMemory(i, 1), ct);
            if ((prefix[i] & 128) == 0)
            {
                int offset = 0; length = ReadVarInt(prefix.AsSpan(0, i + 1), ref offset); break;
            }
            if (i == 4) throw new InvalidDataException("Invalid frame length.");
        }
        if (length is < 1 or > MaxPacket) throw new InvalidDataException("Frame exceeds limit.");
        byte[] frame = new byte[length];
        await stream.ReadExactlyAsync(frame, ct);
        if (compression < 0) return frame;
        int o = 0, uncompressed = ReadVarInt(frame, ref o);
        if (uncompressed == 0)
        {
            if (frame.Length - o >= compression) throw new InvalidDataException("Uncompressed frame exceeds threshold.");
            return frame[o..];
        }
        if (uncompressed < compression || uncompressed > MaxPacket) throw new InvalidDataException("Invalid compressed frame size.");
        using var input = new MemoryStream(frame, o, frame.Length - o, false);
        using var zlib = new ZLibStream(input, CompressionMode.Decompress);
        byte[] result = new byte[uncompressed];
        await zlib.ReadExactlyAsync(result, ct);
        if (zlib.ReadByte() != -1) throw new InvalidDataException("Decompressed frame exceeds declared length.");
        return result;
    }

    public static async Task WriteAsync(Stream stream, byte[] packet, int compression, CancellationToken ct)
    {
        if (packet.Length is < 1 or > MaxPacket) throw new InvalidDataException("Invalid packet size.");
        using var payload = new MemoryStream();
        if (compression >= 0)
        {
            WriteVarInt(payload, packet.Length >= compression ? packet.Length : 0);
            if (packet.Length >= compression)
            {
                using var zlib = new ZLibStream(payload, CompressionLevel.Fastest, leaveOpen: true);
                zlib.Write(packet);
            }
            else payload.Write(packet);
        }
        else payload.Write(packet);
        if (payload.Length > MaxPacket) throw new InvalidDataException("Frame exceeds limit.");
        using var framed = new MemoryStream();
        WriteVarInt(framed, (int)payload.Length); payload.WriteTo(framed);
        await stream.WriteAsync(framed.ToArray(), ct);
        await stream.FlushAsync(ct);
    }

    public static byte[] Handshake(string host, int port, int state, int protocol = 775) => Packet(0, s =>
    {
        WriteVarInt(s, protocol); WriteString(s, host);
        Span<byte> bytes = stackalloc byte[2]; BinaryPrimitives.WriteUInt16BigEndian(bytes, checked((ushort)port));
        s.Write(bytes); WriteVarInt(s, state);
    });

    public static byte[] LoginStart(PlayerProfile profile) => Packet(0, s =>
    { WriteString(s, profile.Name); s.Write(Convert.FromHexString(profile.Id)); });
}
