using Microsoft.Identity.Client;
using Microsoft.Identity.Client.Extensibility;
using TokenVault.Core;

namespace TokenVault.Vault;

public static class OAuthLogin
{
    public static async Task<MinecraftIdentity> LoginAsync(Configuration c, Action<ITokenCache>? configureCache, CancellationToken ct)
    {
        if (!Guid.TryParse(c.ClientId, out _)) throw new UserVisibleException("Set ClientId to your approved public-client application ID.");
        var app = PublicClientApplicationBuilder.Create(c.ClientId)
            .WithAuthority("https://login.microsoftonline.com/consumers")
            .WithRedirectUri($"http://127.0.0.1:{c.OAuthPort}/")
            .Build();
        configureCache?.Invoke(app.UserTokenCache);
        // MSAL automatically adds openid/profile/offline_access. Do not add reserved scopes.
        string[] scopes = ["XboxLive.signin"];
        AuthenticationResult result;
        var account = (await app.GetAccountsAsync()).SingleOrDefault();
        try
        {
            result = await app.AcquireTokenSilent(scopes, account).ExecuteAsync(ct);
        }
        catch (MsalUiRequiredException)
        {
            result = await app.AcquireTokenInteractive(scopes)
                .WithUseEmbeddedWebView(false)
                .WithCustomWebUi(new SystemBrowserUi(c.OAuthPort))
                .WithPrompt(Prompt.SelectAccount)
                .ExecuteAsync(ct);
        }
        using var http = MinecraftApi.CreateHttp();
        return await new MinecraftApi(http).ExchangeAsync(result.AccessToken, ct);
    }
}
