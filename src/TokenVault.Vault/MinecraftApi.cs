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

    public async Task<MinecraftIdentity> ExchangeAsync(string msa, CancellationToken ct, IProgress<string>? progress = null)
    {
        progress?.Report("Connecting your Xbox profile…");
        using var xbox = await PostAsync("https://user.auth.xboxlive.com/user/authenticate", new
        {
            Properties = new { AuthMethod = "RPS", SiteName = "user.auth.xboxlive.com", RpsTicket = "d=" + msa },
            RelyingParty = "http://auth.xboxlive.com", TokenType = "JWT"
        }, ct);
        using var xsts = await PostAsync("https://xsts.auth.xboxlive.com/xsts/authorize", new
        {
            Properties = new { SandboxId = "RETAIL", UserTokens = new[] { xbox.RootElement.GetProperty("Token").GetString()! } },
            RelyingParty = "rp://api.minecraftservices.com/", TokenType = "JWT"
        }, ct);
        progress?.Report("Signing in to Minecraft…");
        string uhs = xsts.RootElement.GetProperty("DisplayClaims").GetProperty("xui")[0].GetProperty("uhs").GetString()!;
        using var mc = await PostAsync("https://api.minecraftservices.com/authentication/login_with_xbox", new
        {
            identityToken = $"XBL3.0 x={uhs};{xsts.RootElement.GetProperty("Token").GetString()}"
        }, ct);
        var token = new SecretValue(mc.RootElement.GetProperty("access_token").GetString()!);
        try
        {
            progress?.Report("Loading your Minecraft profile…");
            using var request = new HttpRequestMessage(HttpMethod.Get, "https://api.minecraftservices.com/minecraft/profile");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token.Reveal());
            using var response = await http.SendAsync(request, ct);
            if (!response.IsSuccessStatusCode) throw new UserVisibleException("This Microsoft account doesn't own Minecraft: Java Edition (no Java profile found).");
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

    // Xbox field names are case-sensitive PascalCase. PostAsJsonAsync's default (web) options camel-case them,
    // which Xbox rejects with HTTP 400, so the payload is serialized exactly as written.
    private static readonly JsonSerializerOptions Exact = new();

    private async Task<JsonDocument> PostAsync(string url, object payload, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, url) { Content = JsonContent.Create(payload, options: Exact) };
        request.Headers.Accept.ParseAdd("application/json");
        if (url.Contains("xboxlive.com", StringComparison.Ordinal)) request.Headers.Add("x-xbl-contract-version", "1");
        using var response = await http.SendAsync(request, ct);
        byte[] body = await response.Content.ReadAsByteArrayAsync(ct);
        if (response.IsSuccessStatusCode) return JsonDocument.Parse(body);
        long xerr = 0;
        try { using var error = JsonDocument.Parse(body); if (error.RootElement.TryGetProperty("XErr", out var x)) x.TryGetInt64(out xerr); }
        catch (JsonException) { }
        throw new UserVisibleException(StepError(new Uri(url).Host, (int)response.StatusCode, xerr));
    }

    public static string StepError(string host, int status, long xerr) => (host, status) switch
    {
        _ when xerr != 0 => XstsError(xerr),
        (_, 429) => "Too many sign-in attempts. Wait a minute, then try again.",
        ("user.auth.xboxlive.com", 400 or 401) => "Xbox didn't accept the Microsoft sign-in. Sign out, then sign in again.",
        ("api.minecraftservices.com", 401 or 403) =>
            "Minecraft didn't accept this sign-in. If you set your own Microsoft app ID, Mojang must approve it first; clear it in Settings to use the built-in one.",
        ("xsts.auth.xboxlive.com", _) => "Xbox couldn't authorize this account for Minecraft. Sign in at xbox.com once, then try again.",
        _ => $"Sign-in failed at {host} (HTTP {status}). Try again in a moment."
    };
}
