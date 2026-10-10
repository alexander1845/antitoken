using System.Buffers;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace TokenVault.Core;

public static class MinecraftCrypto
{
    public static string ServerHash(string serverId, byte[] secret, byte[] publicKey)
    {
        using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA1);
        sha.AppendData(Encoding.Latin1.GetBytes(serverId)); sha.AppendData(secret); sha.AppendData(publicKey);
        var signed = new BigInteger(sha.GetHashAndReset(), isUnsigned: false, isBigEndian: true);
        return (signed.Sign < 0 ? "-" : "") + BigInteger.Abs(signed).ToString("x").TrimStart('0') switch
        { "" => "0", var value => value };
    }

    public static ICryptoTransform CreateCipher(byte[] secret, bool encrypt) => new Cfb8Transform(secret, encrypt);
}

// .NET's CFB transform buffers whole AES blocks on some platforms. Minecraft needs
// immediate one-byte progress. Implement the standard CFB8 mode using platform AES,
// with independent published/independently generated vectors in the test suite.
// Decryption is batched: every shift-register state is made of ciphertext bytes that are already known, so all the
// keystream blocks for a chunk come from one AES-ECB call instead of one call per byte. Encryption is inherently
// sequential (each register needs the previous output), which is fine for the small client-to-server direction.
internal sealed class Cfb8Transform : ICryptoTransform
{
    private const int Chunk = 4096;
    private readonly Aes aes;
    private readonly byte[] register;
    private readonly byte[] block = new byte[16];
    private readonly byte[] joined = new byte[16 + Chunk];      // register followed by this chunk's ciphertext
    private readonly byte[] windows = new byte[16 * Chunk];     // the register state before each byte
    private readonly byte[] keystream = new byte[16 * Chunk];
    private readonly bool encrypt;
    public Cfb8Transform(byte[] key, bool encrypt)
    {
        if (key.Length != 16) throw new ArgumentException("Minecraft requires a 16-byte AES key.");
        aes = Aes.Create(); aes.Key = key;
        register = key.ToArray(); this.encrypt = encrypt;
    }
    public int InputBlockSize => 1;
    public int OutputBlockSize => 1;
    public bool CanTransformMultipleBlocks => true;
    public bool CanReuseTransform => false;
    public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
    {
        if (encrypt)
        {
            for (int i = 0; i < inputCount; i++)
            {
                aes.EncryptEcb(register, block, PaddingMode.None);
                byte transformed = (byte)(inputBuffer[inputOffset + i] ^ block[0]);
                Buffer.BlockCopy(register, 1, register, 0, 15);
                register[15] = transformed;
                outputBuffer[outputOffset + i] = transformed;
            }
            return inputCount;
        }
        for (int done = 0; done < inputCount; done += Chunk)
        {
            int n = Math.Min(Chunk, inputCount - done);
            // Copy the ciphertext first: input and output may be the same buffer.
            Buffer.BlockCopy(register, 0, joined, 0, 16);
            Buffer.BlockCopy(inputBuffer, inputOffset + done, joined, 16, n);
            for (int i = 0; i < n; i++) Buffer.BlockCopy(joined, i, windows, i * 16, 16);
            aes.EncryptEcb(windows.AsSpan(0, n * 16), keystream.AsSpan(0, n * 16), PaddingMode.None);
            for (int i = 0; i < n; i++) outputBuffer[outputOffset + done + i] = (byte)(joined[16 + i] ^ keystream[i * 16]);
            Buffer.BlockCopy(joined, n, register, 0, 16);
        }
        return inputCount;
    }
    public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
    {
        byte[] result = new byte[inputCount]; TransformBlock(inputBuffer, inputOffset, inputCount, result, 0); return result;
    }
    public void Dispose()
    {
        aes.Dispose();
        foreach (byte[] buffer in new[] { register, block, joined, windows, keystream }) CryptographicOperations.ZeroMemory(buffer);
    }
}

// Streaming CFB8, no block padding, independent continuous state per direction.
public sealed class CipherStream(Stream inner, byte[] secret) : Stream
{
    private readonly ICryptoTransform encryptor = MinecraftCrypto.CreateCipher(secret, true);
    private readonly ICryptoTransform decryptor = MinecraftCrypto.CreateCipher(secret, false);
    public override bool CanRead => true;
    public override bool CanWrite => true;
    public override bool CanSeek => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    public override void Flush() => inner.Flush();
    public override Task FlushAsync(CancellationToken cancellationToken) => inner.FlushAsync(cancellationToken);
    public override int Read(byte[] buffer, int offset, int count)
    {
        int n = inner.Read(buffer, offset, count);
        if (n > 0) decryptor.TransformBlock(buffer, offset, n, buffer, offset);
        return n;
    }
    // Runs for every packet while playing: decrypts in the caller's buffer when it's an array (the relay's always is),
    // so there's no allocation or extra copy per read.
    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (MemoryMarshal.TryGetArray<byte>(buffer, out var segment))
        {
            int read = await inner.ReadAsync(buffer, cancellationToken);
            if (read > 0) decryptor.TransformBlock(segment.Array!, segment.Offset, read, segment.Array!, segment.Offset);
            return read;
        }
        byte[] temp = ArrayPool<byte>.Shared.Rent(buffer.Length);
        try
        {
            int n = await inner.ReadAsync(temp.AsMemory(0, buffer.Length), cancellationToken);
            if (n > 0) decryptor.TransformBlock(temp, 0, n, temp, 0);
            temp.AsMemory(0, n).CopyTo(buffer); return n;
        }
        finally { CryptographicOperations.ZeroMemory(temp); ArrayPool<byte>.Shared.Return(temp); }
    }
    public override void Write(byte[] buffer, int offset, int count)
    {
        byte[] temp = new byte[count];
        try { encryptor.TransformBlock(buffer, offset, count, temp, 0); inner.Write(temp); }
        finally { CryptographicOperations.ZeroMemory(temp); }
    }
    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        int count = buffer.Length;
        byte[] temp = ArrayPool<byte>.Shared.Rent(count);
        try
        {
            buffer.Span.CopyTo(temp);
            encryptor.TransformBlock(temp, 0, count, temp, 0);
            await inner.WriteAsync(temp.AsMemory(0, count), cancellationToken);
        }
        finally { CryptographicOperations.ZeroMemory(temp.AsSpan(0, count)); ArrayPool<byte>.Shared.Return(temp); }
    }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    protected override void Dispose(bool disposing)
    { if (disposing) { encryptor.Dispose(); decryptor.Dispose(); } base.Dispose(disposing); }
}
