using System.Security.Cryptography;
using System.Text;

namespace TokenVault.Vault;

// Strings produced for MSAL / HTTP cannot be reliably erased by .NET. Never log them.
public sealed class SecretValue : IDisposable
{
    private byte[]? bytes;
    public SecretValue(string value) => bytes = Encoding.UTF8.GetBytes(value);
    internal string Reveal() => Encoding.UTF8.GetString(bytes ?? throw new ObjectDisposedException(nameof(SecretValue)));
    public bool OccursIn(ReadOnlySpan<byte> data) => bytes is not null && data.IndexOf(bytes) >= 0;
    public override string ToString() => "[REDACTED]";
    public void Dispose()
    {
        if (bytes is not null) CryptographicOperations.ZeroMemory(bytes);
        bytes = null;
    }
}
