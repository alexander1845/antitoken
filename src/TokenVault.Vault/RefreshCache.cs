using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Microsoft.Identity.Client;
using TokenVault.Core;

namespace TokenVault.Vault;

public static class RefreshCacheFilter
{
    // Pinned MSAL v3 serialization schema. Unknown categories fail closed.
    public static byte[] Filter(byte[] serialized)
    {
        var root = JsonNode.Parse(serialized)?.AsObject() ?? throw new InvalidDataException("Invalid MSAL cache.");
        foreach (var key in root.Select(p => p.Key).ToArray())
        {
            if (key is "AccessToken" or "IdToken") root[key] = new JsonObject();
            else if (key is not ("Account" or "RefreshToken" or "AppMetadata"))
                throw new InvalidDataException("Unsupported MSAL cache schema; refusing persistence.");
        }
        return System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(root);
    }
}

// The refresh token at rest. Since v2 it is envelope-encrypted (AES-256-GCM, see Envelope) under a fresh key that is
// wrapped by this PC's TPM and DPAPI (or DPAPI alone when there is no usable TPM). The context string binds the file
// to its purpose and to this Windows user. v1 files (plain DPAPI) are still read and are rewritten as v2.
[SupportedOSPlatform("windows")]
public sealed class RefreshCache(string file)
{
    private static readonly byte[] Entropy = "TokenVault.RefreshCache.v1"u8.ToArray(); // Public domain separation, not a secret.
    private static readonly string Context = "TokenVault.RefreshCache.v2|" + System.Security.Principal.WindowsIdentity.GetCurrent().User?.Value;
    private readonly DpapiKeyWrap dpapi = new(Entropy);
    private TpmKeyWrap? tpm;
    private bool loaded, tpmChecked; // the TPM is probed once per run, not on every save

    public bool Exists => File.Exists(file);

    // How the saved sign-in is protected, for the Security page.
    public static string Protection(string file)
    {
        try
        {
            byte[] head = new byte[6];
            using (var stream = File.OpenRead(file)) if (stream.Read(head) < head.Length) return "DPAPI";
            return !Envelope.IsEnvelope(head) ? "DPAPI" : head[5] == TpmKeyWrap.WrapId ? "TPM + DPAPI, AES-256-GCM" : "DPAPI, AES-256-GCM";
        }
        catch (IOException) { return "unknown"; }
    }

    // Local sign-out. Deleting the TPM key also makes any stray copy of the file (backup, disk image) unreadable.
    // The refresh token stays valid at Microsoft until it expires or is revoked there.
    public void Delete()
    {
        File.Delete(file);
        File.Delete(file + ".new");
        TpmKeyWrap.Delete();
    }

    private IKeyWrap? Resolve(byte id) => id switch
    {
        DpapiKeyWrap.WrapId => dpapi,
        TpmKeyWrap.WrapId => tpm ??= TpmKeyWrap.TryOpen(dpapi, create: false),
        _ => null
    };

    public void Attach(ITokenCache cache)
    {
        cache.SetBeforeAccess(args =>
        {
            if (loaded) return;
            if (File.Exists(file))
            {
                byte[] stored = File.ReadAllBytes(file);
                byte[]? plain = null;
                try
                {
                    plain = Envelope.IsEnvelope(stored) ? Envelope.Open(stored, Context, Resolve)
                        : ProtectedData.Unprotect(stored, Entropy, DataProtectionScope.CurrentUser);
                    args.TokenCache.DeserializeMsalV3(plain, shouldClearExistingCache: true);
                }
                catch (CryptographicException)
                {
                    // Tampered, from another PC/user, or its TPM key is gone (TPM cleared): forget it and sign in again.
                    File.Delete(file);
                }
                finally { if (plain is not null) CryptographicOperations.ZeroMemory(plain); }
            }
            loaded = true;
        });
        cache.SetAfterAccess(args =>
        {
            if (!args.HasStateChanged) return;
            byte[] full = args.TokenCache.SerializeMsalV3();
            byte[]? filtered = null;
            try
            {
                filtered = RefreshCacheFilter.Filter(full);
                if (tpm is null && !tpmChecked) { tpmChecked = true; tpm = TpmKeyWrap.TryOpen(dpapi, create: true); }
                byte[] protectedBytes = Envelope.Seal(filtered, Context, (IKeyWrap?)tpm ?? dpapi);
                Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(file))!);
                string temp = file + ".new";
                using (var stream = new FileStream(temp, FileMode.Create, FileAccess.Write, FileShare.None,
                           4096, FileOptions.WriteThrough))
                {
                    stream.Write(protectedBytes);
                    stream.Flush(flushToDisk: true);
                }
                File.Move(temp, file, overwrite: true);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(full);
                if (filtered is not null) CryptographicOperations.ZeroMemory(filtered);
            }
        });
    }
}
