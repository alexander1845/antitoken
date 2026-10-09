using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using TokenVault.Core;

namespace TokenVault.Vault;

public sealed record MinecraftIdentity(SecretValue Token, PlayerProfile Profile, DateTimeOffset ExpiresAt) : IDisposable
{
    public void Dispose() => Token.Dispose();
}

public sealed class MinecraftApi(HttpClient http)
{
    public static HttpClient CreateHttp() => new(new SocketsHttpHandler
    {
        AllowAutoRedirect = false,
        UseProxy = false,
        UseCookies = false,
        AutomaticDecompression = DecompressionMethods.None
    }) { Timeout = TimeSpan.FromSeconds(25), MaxResponseContentBufferSize = 2 * 1024 * 1024 };

    public async Task<MinecraftIdentity> ExchangeAsync(string msa, CancellationToken ct)
    {
        using var xbox = await PostAsync("https://user.auth.xboxlive.com/user/authenticate", new
        {
            Properties = new { AuthMethod = "RPS", SiteName = "user.auth.xboxlive.com", RpsTicket = "d=" + msa },
            RelyingParty = "http://auth.xboxlive.com", TokenType = "JWT"
        }, ct);
        using var xstsResponse = await http.PostAsJsonAsync("https://xsts.auth.xboxlive.com/xsts/authorize", new
        {
            Properties = new { SandboxId = "RETAIL", UserTokens = new[] { xbox.RootElement.GetProperty("Token").GetString()! } },
            RelyingParty = "rp://api.minecraftservices.com/", TokenType = "JWT"
        }, ct);
        using var xsts = await JsonDocument.ParseAsync(await xstsResponse.Content.ReadAsStreamAsync(ct), cancellationToken: ct);
        if (!xstsResponse.IsSuccessStatusCode)
        {
            long code = xsts.RootElement.TryGetProperty("XErr", out var x) && x.TryGetInt64(out var n) ? n : 0;
            throw new UserVisibleException(XstsError(code));
        }
        string uhs = xsts.RootElement.GetProperty("DisplayClaims").GetProperty("xui")[0].GetProperty("uhs").GetString()!;
        using var mc = await PostAsync("https://api.minecraftservices.com/authentication/login_with_xbox", new
        {
            identityToken = $"XBL3.0 x={uhs};{xsts.RootElement.GetProperty("Token").GetString()}"
        }, ct);
        var token = new SecretValue(mc.RootElement.GetProperty("access_token").GetString()!);
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, "https://api.minecraftservices.com/minecraft/profile");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token.Reveal());
            using var response = await http.SendAsync(request, ct);
            if (!response.IsSuccessStatusCode) throw new UserVisibleException("Minecraft profile unavailable. Check Java Edition ownership and application approval.");
            using var profile = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync(ct), cancellationToken: ct);
            var p = new PlayerProfile(profile.RootElement.GetProperty("id").GetString()!, profile.RootElement.GetProperty("name").GetString()!);
            if (!Guid.TryParseExact(p.Id, "N", out _) || p.Name.Length is < 1 or > 16)
                throw new InvalidDataException("Invalid Minecraft profile.");
            return new(token, p, DateTimeOffset.UtcNow.AddSeconds(mc.RootElement.GetProperty("expires_in").GetInt32()));
        }
        catch { token.Dispose(); throw; }
    }

    public static string XstsError(long code) => code switch
    {
        2148916233 => "This Microsoft account has no Xbox profile. Create one at xbox.com, then retry.",
        2148916235 => "Xbox Live is unavailable for this account's region.",
        2148916236 or 2148916237 => "Xbox requires age or adult verification for this account.",
        2148916238 => "This child account needs a Microsoft family organizer to approve Xbox access.",
        _ => $"Xbox authorization failed (XErr {code}). Check account permissions."
    };

    private async Task<JsonDocument> PostAsync(string url, object payload, CancellationToken ct)
    {
        using var response = await http.PostAsJsonAsync(url, payload, ct);
        if (!response.IsSuccessStatusCode)
            throw new UserVisibleException($"Authentication step at {new Uri(url).Host} failed (HTTP {(int)response.StatusCode}). Check account/app approval.");
        return await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync(ct), cancellationToken: ct);
    }
}
