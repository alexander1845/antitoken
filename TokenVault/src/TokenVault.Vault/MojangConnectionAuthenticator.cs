using System.Net;
using System.Net.Http.Json;

namespace TokenVault.Vault;

public sealed class MojangConnectionAuthenticator(HttpClient http, MinecraftIdentity identity) : IConnectionAuthenticator
{
    public async Task AuthorizeOwnedConnectionAsync(string serverHash, CancellationToken ct)
    {
        if (DateTimeOffset.UtcNow >= identity.ExpiresAt.AddSeconds(-30)) throw new InvalidOperationException("Session expired; restart the vault.");
        using var response = await http.PostAsJsonAsync("https://sessionserver.mojang.com/session/minecraft/join",
            new { accessToken = identity.Token.Reveal(), selectedProfile = identity.Profile.Id, serverId = serverHash }, ct);
        if (response.StatusCode != HttpStatusCode.NoContent) throw new InvalidOperationException("Mojang refused the owned connection.");
    }
}
