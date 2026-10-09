using System.Runtime.Versioning;
using System.Security.Cryptography;
using TokenVault.Core;

namespace TokenVault.Vault;

// DPAPI (CurrentUser): the key can only be unwrapped while logged in as this Windows user.
[SupportedOSPlatform("windows")]
public sealed class DpapiKeyWrap(byte[] entropy) : IKeyWrap
{
    public const byte WrapId = 1;
    public byte Id => WrapId;
    public byte[] Wrap(byte[] key) => ProtectedData.Protect(key, entropy, DataProtectionScope.CurrentUser);
    public byte[] Unwrap(byte[] wrapped) => ProtectedData.Unprotect(wrapped, entropy, DataProtectionScope.CurrentUser);
}

// TPM, then DPAPI. The key is first encrypted (RSA-OAEP-SHA256) to a non-exportable RSA key that lives inside this PC's
// TPM, then DPAPI-wrapped. Unwrapping needs both this Windows user's DPAPI keys and this physical TPM, so a copied
// file, disk image or backup is useless elsewhere, even with the user's password (DPAPI alone falls to that).
[SupportedOSPlatform("windows")]
public sealed class TpmKeyWrap : IKeyWrap
{
    public const byte WrapId = 2;
    private const string KeyName = "TokenVault.RefreshCache.TpmKey.v2";
    private static readonly CngProvider Platform = new("Microsoft Platform Crypto Provider");
    private readonly DpapiKeyWrap dpapi;
    private readonly CngKey key;

    private TpmKeyWrap(CngKey key, DpapiKeyWrap dpapi) { this.key = key; this.dpapi = dpapi; }
    public byte Id => WrapId;

    public byte[] Wrap(byte[] dek)
    {
        using var rsa = new RSACng(key);
        byte[] sealedKey = rsa.Encrypt(dek, RSAEncryptionPadding.OaepSHA256);
        return dpapi.Wrap(sealedKey);
    }

    public byte[] Unwrap(byte[] wrapped)
    {
        byte[] sealedKey = dpapi.Unwrap(wrapped);
        using var rsa = new RSACng(key);
        return rsa.Decrypt(sealedKey, RSAEncryptionPadding.OaepSHA256);
    }

    // Opens the TPM key, or creates it (create: false only opens). Returns null when there is no usable TPM, or when
    // a full wrap/unwrap round trip fails, so callers fall back to DPAPI alone instead of storing something unreadable.
    public static TpmKeyWrap? TryOpen(DpapiKeyWrap dpapi, bool create)
    {
        try
        {
            CngKey key;
            if (CngKey.Exists(KeyName, Platform)) key = CngKey.Open(KeyName, Platform);
            else if (!create) return null;
            else
            {
                var parameters = new CngKeyCreationParameters
                {
                    Provider = Platform,
                    ExportPolicy = CngExportPolicies.None, // private key never leaves the TPM
                    KeyUsage = CngKeyUsages.Decryption,
                    KeyCreationOptions = CngKeyCreationOptions.None
                };
                parameters.Parameters.Add(new CngProperty("Length", BitConverter.GetBytes(2048), CngPropertyOptions.None));
                key = CngKey.Create(CngAlgorithm.Rsa, KeyName, parameters);
            }
            var wrap = new TpmKeyWrap(key, dpapi);
            byte[] probe = RandomNumberGenerator.GetBytes(32);
            try
            {
                byte[] back = wrap.Unwrap(wrap.Wrap(probe));
                bool ok = CryptographicOperations.FixedTimeEquals(back, probe);
                CryptographicOperations.ZeroMemory(back);
                if (ok) return wrap;
            }
            finally { CryptographicOperations.ZeroMemory(probe); }
            key.Dispose();
            return null;
        }
        catch (CryptographicException) { return null; } // no TPM, TPM disabled, or the provider refused
        catch (PlatformNotSupportedException) { return null; }
    }

    // Removes the TPM key (sign-out). Without it, any copy of the old file can never be opened again.
    public static void Delete()
    {
        try { if (CngKey.Exists(KeyName, Platform)) CngKey.Open(KeyName, Platform).Delete(); }
        catch (CryptographicException) { }
    }
}
