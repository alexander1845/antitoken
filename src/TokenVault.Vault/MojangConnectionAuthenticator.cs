using System.Net;
using System.Net.Http.Json;

namespace TokenVault.Vault;

public sealed class MojangConnectionAuthenticator(HttpClient http, MinecraftIdentity identity) : IConnectionAuthenticator
{
    public async Task AuthorizeOwnedConnectionAsync(string serverHash, CancellationToken ct)
    {
        if (DateTimeOffset.UtcNow >= identity.ExpiresAt.AddSeconds(-30)) throw new SessionExpiredException();
        using var response = await http.PostAsJsonAsync("https://sessionserver.mojang.com/session/minecraft/join",
            new { accessToken = identity.Token.Reveal(), selectedProfile = identity.Profile.Id, serverId = serverHash }, ct);
        if (response.StatusCode == HttpStatusCode.NoContent) return;
        throw new MojangJoinException(response.StatusCode switch
        {
            HttpStatusCode.Forbidden => "Minecraft refused to sign you in to servers. Multiplayer may be turned off for this account (Xbox privacy settings).",
            HttpStatusCode.Unauthorized => "your sign-in expired. Sign out in Token Vault, sign in again and press Play.",
            HttpStatusCode.TooManyRequests => "Minecraft's sign-in service is rate limiting. Wait a minute and try again.",
            _ => $"Minecraft's sign-in service refused the join (HTTP {(int)response.StatusCode}). Try again."
        });
    }
}

public sealed class MojangJoinException(string message) : Exception(message);
