using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace TokenVault.Core;

// Protects a small key (the data-encryption key) with something outside this file: DPAPI, a TPM key, or both.
public interface IKeyWrap
{
    byte Id { get; }
    byte[] Wrap(byte[] key);
    byte[] Unwrap(byte[] wrapped);
}

// Versioned envelope encryption for secrets at rest (see docs/CRYPTOGRAPHY.md, "Data at rest").
//
//   "TVE1" | version (2) | wrap id | u16 wrapped-key length | wrapped key | nonce (12) | ciphertext | tag (16)
//
// Every Seal draws a fresh 256-bit data-encryption key (DEK), so a (key, nonce) pair is never reused even if the
// random nonce repeated. AES-256-GCM authenticates the ciphertext AND, as associated data, the header plus a caller
// context string. Changing the version, the wrap method, the wrapped key or moving the blob to another purpose or
// Windows user therefore fails authentication instead of decrypting to something else.
public static class Envelope
{
    private static readonly byte[] Magic = "TVE1"u8.ToArray();
    private const byte Version = 2;
    private const int NonceSize = 12, TagSize = 16, KeySize = 32;

    public static bool IsEnvelope(ReadOnlySpan<byte> blob) => blob.Length > Magic.Length && blob[..Magic.Length].SequenceEqual(Magic);

    public static byte[] Seal(ReadOnlySpan<byte> plaintext, string context, IKeyWrap wrap)
    {
        byte[] dek = RandomNumberGenerator.GetBytes(KeySize);
        try
        {
            byte[] wrapped = wrap.Wrap(dek);
            if (wrapped.Length > ushort.MaxValue) throw new CryptographicException("Wrapped key too large.");
            int headerLength = Magic.Length + 4 + wrapped.Length;
            byte[] blob = new byte[headerLength + NonceSize + plaintext.Length + TagSize];
            Magic.CopyTo(blob, 0);
            blob[4] = Version;
            blob[5] = wrap.Id;
            BinaryPrimitives.WriteUInt16BigEndian(blob.AsSpan(6), (ushort)wrapped.Length);
            wrapped.CopyTo(blob, 8);
            var nonce = blob.AsSpan(headerLength, NonceSize);
            RandomNumberGenerator.Fill(nonce);
            using var gcm = new AesGcm(dek, TagSize);
            gcm.Encrypt(nonce, plaintext, blob.AsSpan(headerLength + NonceSize, plaintext.Length),
                blob.AsSpan(blob.Length - TagSize), AssociatedData(blob.AsSpan(0, headerLength), context));
            return blob;
        }
        finally { CryptographicOperations.ZeroMemory(dek); }
    }

    // resolve maps the wrap id stored in the header to the matching unwrapper (null: unknown or unavailable).
    public static byte[] Open(ReadOnlySpan<byte> blob, string context, Func<byte, IKeyWrap?> resolve)
    {
        if (!IsEnvelope(blob) || blob.Length < 8) throw new CryptographicException("Not a Token Vault envelope.");
        if (blob[4] != Version) throw new CryptographicException("Unsupported envelope version.");
        int wrappedLength = BinaryPrimitives.ReadUInt16BigEndian(blob[6..]);
        int headerLength = 8 + wrappedLength;
        if (blob.Length < headerLength + NonceSize + TagSize) throw new CryptographicException("Truncated envelope.");
        var wrap = resolve(blob[5]) ?? throw new CryptographicException("The key protecting this data is not available on this PC.");
        byte[] dek = wrap.Unwrap(blob.Slice(8, wrappedLength).ToArray());
        try
        {
            if (dek.Length != KeySize) throw new CryptographicException("Invalid data-encryption key.");
            var ciphertext = blob[(headerLength + NonceSize)..^TagSize];
            byte[] plaintext = new byte[ciphertext.Length];
            using var gcm = new AesGcm(dek, TagSize);
            try
            {
                gcm.Decrypt(blob.Slice(headerLength, NonceSize), ciphertext, blob[^TagSize..], plaintext,
                    AssociatedData(blob[..headerLength], context));
            }
            catch { CryptographicOperations.ZeroMemory(plaintext); throw; }
            return plaintext;
        }
        finally { CryptographicOperations.ZeroMemory(dek); }
    }

    private static byte[] AssociatedData(ReadOnlySpan<byte> header, string context)
    {
        byte[] label = Encoding.UTF8.GetBytes(context);
        byte[] data = new byte[header.Length + 4 + label.Length];
        header.CopyTo(data);
        BinaryPrimitives.WriteInt32BigEndian(data.AsSpan(header.Length), label.Length); // length-prefixed: no ambiguity
        label.CopyTo(data, header.Length + 4);
        return data;
    }
}
