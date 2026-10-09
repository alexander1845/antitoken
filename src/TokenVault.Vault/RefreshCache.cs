using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Microsoft.Identity.Client;

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

[SupportedOSPlatform("windows")]
public sealed class RefreshCache(string file)
{
    private static readonly byte[] Entropy = "TokenVault.RefreshCache.v1"u8.ToArray(); // Public domain separation, not a secret.
    private bool loaded;

    public bool Exists => File.Exists(file);

    // Local sign-out only. The refresh token stays valid at Microsoft until it expires or is revoked there.
    public void Delete()
    {
        File.Delete(file);
        File.Delete(file + ".new");
    }

    public void Attach(ITokenCache cache)
    {
        cache.SetBeforeAccess(args =>
        {
            if (loaded) return;
            if (File.Exists(file))
            {
                byte[] encrypted = File.ReadAllBytes(file);
                byte[] plain = ProtectedData.Unprotect(encrypted, Entropy, DataProtectionScope.CurrentUser);
                try { args.TokenCache.DeserializeMsalV3(plain, shouldClearExistingCache: true); }
                finally { CryptographicOperations.ZeroMemory(plain); }
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
                byte[] protectedBytes = ProtectedData.Protect(filtered, Entropy, DataProtectionScope.CurrentUser);
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
