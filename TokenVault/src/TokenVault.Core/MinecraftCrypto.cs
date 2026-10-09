using System.Numerics;
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
internal sealed class Cfb8Transform : ICryptoTransform
{
    private readonly ICryptoTransform aes;
    private readonly byte[] register;
    private readonly byte[] output = new byte[16];
    private readonly bool encrypt;
    public Cfb8Transform(byte[] key, bool encrypt)
    {
        if (key.Length != 16) throw new ArgumentException("Minecraft requires a 16-byte AES key.");
        using var algorithm = Aes.Create();
        algorithm.Mode = CipherMode.ECB; algorithm.Padding = PaddingMode.None; algorithm.Key = key;
        aes = algorithm.CreateEncryptor(); register = key.ToArray(); this.encrypt = encrypt;
    }
    public int InputBlockSize => 1;
    public int OutputBlockSize => 1;
    public bool CanTransformMultipleBlocks => true;
    public bool CanReuseTransform => false;
    public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
    {
        for (int i = 0; i < inputCount; i++)
        {
            aes.TransformBlock(register, 0, 16, output, 0);
            byte source = inputBuffer[inputOffset + i];
            byte transformed = (byte)(source ^ output[0]);
            Buffer.BlockCopy(register, 1, register, 0, 15);
            register[15] = encrypt ? transformed : source;
            outputBuffer[outputOffset + i] = transformed;
        }
        return inputCount;
    }
    public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
    {
        byte[] result = new byte[inputCount]; TransformBlock(inputBuffer, inputOffset, inputCount, result, 0); return result;
    }
    public void Dispose() { aes.Dispose(); CryptographicOperations.ZeroMemory(register); CryptographicOperations.ZeroMemory(output); }
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
    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        byte[] temp = new byte[buffer.Length];
        try
        {
            int n = await inner.ReadAsync(temp, cancellationToken);
            if (n > 0) decryptor.TransformBlock(temp, 0, n, temp, 0);
            temp.AsMemory(0, n).CopyTo(buffer); return n;
        }
        finally { CryptographicOperations.ZeroMemory(temp); }
    }
    public override void Write(byte[] buffer, int offset, int count)
    {
        byte[] temp = new byte[count];
        try { encryptor.TransformBlock(buffer, offset, count, temp, 0); inner.Write(temp); }
        finally { CryptographicOperations.ZeroMemory(temp); }
    }
    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        byte[] temp = buffer.ToArray();
        try { encryptor.TransformBlock(temp, 0, temp.Length, temp, 0); await inner.WriteAsync(temp, cancellationToken); }
        finally { CryptographicOperations.ZeroMemory(temp); }
    }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    protected override void Dispose(bool disposing)
    { if (disposing) { encryptor.Dispose(); decryptor.Dispose(); } base.Dispose(disposing); }
}
