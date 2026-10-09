using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace TokenVault.Core;

public static class FakeToken
{
    public static string Create(PlayerProfile profile, DateTimeOffset expiresAt)
    {
        static string B64(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        byte[] random = RandomNumberGenerator.GetBytes(64);
        try
        {
            return B64(Encoding.UTF8.GetBytes("{\"alg\":\"RS256\",\"typ\":\"JWT\"}")) + "." +
                B64(JsonSerializer.SerializeToUtf8Bytes(new
                {
                    sub = profile.Id, username = profile.Name, aud = "minecraftservices",
                    iss = "token-vault.invalid", iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                    exp = expiresAt.ToUnixTimeSeconds(), jti = B64(random[..32])
                })) + "." + B64(random[32..]);
        }
        finally { CryptographicOperations.ZeroMemory(random); }
    }
}
