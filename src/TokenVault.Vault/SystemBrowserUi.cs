using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Identity.Client.Extensibility;
using TokenVault.Core;

namespace TokenVault.Vault;

// MSAL owns PKCE, state construction and code redemption. This adapter only opens
// the OS browser and receives the redirect on an explicitly IPv4-loopback socket.
// MSAL's default HttpListener helper binds "localhost", not literal 127.0.0.1.
public sealed class SystemBrowserUi(int port, Func<Uri, Task>? openBrowserForTest = null) : ICustomWebUi
{
    public async Task<Uri> AcquireAuthorizationCodeAsync(Uri authorizationUri, Uri redirectUri, CancellationToken cancellationToken)
    {
        var query = QueryHelpers.ParseQuery(authorizationUri.Query);
        string state = query.GetValueOrDefault("state").ToString();
        if (authorizationUri.Scheme != "https" || authorizationUri.Host != "login.microsoftonline.com" ||
            query.GetValueOrDefault("code_challenge_method") != "S256" || query.GetValueOrDefault("code_challenge").ToString().Length < 43 || state.Length < 16 ||
            redirectUri.Scheme != "http" || redirectUri.Host != "127.0.0.1" || redirectUri.Port != port || redirectUri.AbsolutePath != "/")
            throw new UserVisibleException("Unexpected OAuth redirect or missing PKCE; authentication refused.");
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromMinutes(10));
        var completed = new TaskCompletionSource<Uri>(TaskCreationOptions.RunContinuationsAsynchronously);
        var builder = WebApplication.CreateSlimBuilder(new WebApplicationOptions { Args = [], ApplicationName = typeof(SystemBrowserUi).Assembly.FullName });
        builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(options =>
        {
            options.AddServerHeader = false; options.Limits.MaxRequestBodySize = 16384;
            options.Limits.MaxConcurrentConnections = 8;
            options.Listen(IPAddress.Loopback, port);
        });
        await using var app = builder.Build();
        app.Run(async context =>
        {
            context.Response.Headers.CacheControl = "no-store";
            context.Response.Headers["Referrer-Policy"] = "no-referrer";
            context.Response.Headers["Content-Security-Policy"] = "default-src 'none'";
            if (context.Request.Path != "/" || context.Request.Host.Host != "127.0.0.1" ||
                !IPAddress.IsLoopback(context.Connection.RemoteIpAddress ?? IPAddress.None))
            { context.Response.StatusCode = 404; return; }
            Dictionary<string, string?> fields;
            if (context.Request.Method == "GET") fields = context.Request.Query.ToDictionary(p => p.Key, p => (string?)p.Value.ToString());
            else if (context.Request.Method == "POST" && context.Request.HasFormContentType)
                fields = (await context.Request.ReadFormAsync(context.RequestAborted)).ToDictionary(p => p.Key, p => (string?)p.Value.ToString());
            else { context.Response.StatusCode = 405; return; }
            if (!fields.TryGetValue("state", out var returnedState) || returnedState is null ||
                !CryptographicOperations.FixedTimeEquals(SHA256.HashData(Encoding.UTF8.GetBytes(state)), SHA256.HashData(Encoding.UTF8.GetBytes(returnedState))))
            { context.Response.StatusCode = 403; return; }
            if (!fields.ContainsKey("code") && !fields.ContainsKey("error")) { context.Response.StatusCode = 400; return; }
            var callbackFields = fields.Where(p => p.Key is "code" or "state" or "error" or "error_description").ToDictionary(p => p.Key, p => p.Value);
            var callback = new Uri(QueryHelpers.AddQueryString(redirectUri.AbsoluteUri, callbackFields));
            context.Response.ContentType = "text/plain; charset=utf-8";
            await context.Response.WriteAsync("Signed in. Return to the Token Vault window; you may close this tab.", context.RequestAborted);
            await context.Response.CompleteAsync();
            completed.TrySetResult(callback);
        });
        await app.StartAsync(deadline.Token);
        try
        {
            if (openBrowserForTest is not null) await openBrowserForTest(authorizationUri);
            else OpenBrowser(authorizationUri);
            return await completed.Task.WaitAsync(deadline.Token);
        }
        finally { await app.StopAsync(CancellationToken.None); }
    }

    // Opens the default browser. Some PCs have a broken "https" association, so Explorer is asked as a fallback.
    private static void OpenBrowser(Uri page)
    {
        try { Process.Start(new ProcessStartInfo(page.AbsoluteUri) { UseShellExecute = true })?.Dispose(); }
        catch (System.ComponentModel.Win32Exception) when (OperatingSystem.IsWindows())
        {
            try { Process.Start(new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe")) { ArgumentList = { page.AbsoluteUri } })?.Dispose(); }
            catch (System.ComponentModel.Win32Exception)
            {
                throw new UserVisibleException("Windows couldn't open your web browser for sign-in. Turn on \"Sign in with a code\" in Settings and try again.");
            }
        }
    }
}
