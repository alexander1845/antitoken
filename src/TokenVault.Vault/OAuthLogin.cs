using Microsoft.Identity.Client;
using Microsoft.Identity.Client.Extensibility;
using TokenVault.Core;

namespace TokenVault.Vault;

public static class AuthenticationDefaults
{
    // Microsoft sign-in always needs SOME registered public client ID. With none configured, Token Vault uses the
    // public ID Prism Launcher publishes in its source (not a secret), so testing needs no registration.
    // Microsoft's consent page will name "Prism Launcher". Distributed builds should set their own ClientId.
    public const string BuiltInClientId = "c36a9fb6-4f2a-41ff-90bd-ae7cc92031eb";
    public const string BuiltInClientName = "Prism Launcher";

    public static string Resolve(Configuration c) => c.ClientId.Length > 0 ? c.ClientId : BuiltInClientId;
}

public sealed record SignInOptions
{
    public bool UseDeviceCode { get; init; }
    public IProgress<string>? Progress { get; init; }
    // Receives only the short user code and Microsoft's verification page. MSAL keeps the device secret.
    public Func<string, Uri, Task>? ShowDeviceCode { get; init; }
}

public static class OAuthLogin
{
    public static async Task<MinecraftIdentity> LoginAsync(Configuration c, Action<ITokenCache>? configureCache, CancellationToken ct,
        SignInOptions? options = null)
    {
        options ??= new();
        var app = PublicClientApplicationBuilder.Create(AuthenticationDefaults.Resolve(c))
            .WithAuthority("https://login.microsoftonline.com/consumers")
            .WithRedirectUri($"http://127.0.0.1:{c.OAuthPort}/")
            .Build();
        configureCache?.Invoke(app.UserTokenCache);
        // MSAL automatically adds openid/profile/offline_access. Do not add reserved scopes.
        string[] scopes = ["XboxLive.signin"];
        AuthenticationResult result;
        var accounts = (await app.GetAccountsAsync()).ToArray();
        try
        {
            // Never silently pick one account out of several.
            if (accounts.Length != 1) throw new MsalUiRequiredException("no_single_account", "Interactive sign-in required.");
            options.Progress?.Report("Using your saved sign-in…");
            result = await app.AcquireTokenSilent(scopes, accounts[0]).ExecuteAsync(ct);
        }
        catch (MsalUiRequiredException)
        {
            if (options.UseDeviceCode)
            {
                if (options.ShowDeviceCode is null) throw new UserVisibleException("Sign-in with a code is not available here.");
                options.Progress?.Report("Getting a sign-in code from Microsoft…");
                result = await app.AcquireTokenWithDeviceCode(scopes, async code =>
                {
                    if (!Uri.TryCreate(code.VerificationUrl, UriKind.Absolute, out var page) || page.Scheme != "https" ||
                        page.Host is not ("microsoft.com" or "www.microsoft.com" or "login.microsoftonline.com" or "login.live.com") ||
                        string.IsNullOrWhiteSpace(code.UserCode) || code.UserCode.Length > 32 || code.UserCode.Any(char.IsControl))
                        throw new UserVisibleException("Microsoft returned an unexpected sign-in page. Try again.");
                    await options.ShowDeviceCode(code.UserCode, page);
                }).ExecuteAsync(ct);
            }
            else
            {
                options.Progress?.Report("Finish signing in in the browser window that just opened…");
                result = await app.AcquireTokenInteractive(scopes)
                    .WithUseEmbeddedWebView(false)
                    .WithCustomWebUi(new SystemBrowserUi(c.OAuthPort))
                    .WithPrompt(Prompt.SelectAccount)
                    .ExecuteAsync(ct);
            }
        }
        using var http = MinecraftApi.CreateHttp();
        return await new MinecraftApi(http).ExchangeAsync(result.AccessToken, ct, options.Progress);
    }
}
