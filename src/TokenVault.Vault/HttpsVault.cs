using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using TokenVault.Core;

namespace TokenVault.Vault;

public sealed class HttpsVault(Configuration config, MinecraftIdentity identity, string fakeToken,
    X509Certificate2 certificate, HttpClient http, Action<string> audit)
{
    private readonly Queue<long> calls = new();
    private readonly byte[] fakeDigest = SHA256.HashData(Encoding.UTF8.GetBytes(fakeToken));

    public WebApplication Create()
    {
        var builder = WebApplication.CreateSlimBuilder(new WebApplicationOptions { Args = [], ApplicationName = typeof(HttpsVault).Assembly.FullName });
        builder.Logging.ClearProviders(); // No request bodies, bearer headers, exception dumps or query strings.
        builder.WebHost.ConfigureKestrel(server =>
        {
            server.AddServerHeader = false;
            server.Limits.MaxRequestBodySize = 8192;
            server.Limits.MaxConcurrentConnections = 16;
            server.Limits.RequestHeadersTimeout = TimeSpan.FromSeconds(10);
            server.Listen(IPAddress.Loopback, config.HttpsPort, listen => listen.UseHttps(certificate));
        });
        var app = builder.Build();
        app.Run(HandleAsync);
        return app;
    }

    private async Task HandleAsync(HttpContext context)
    {
        string path = context.Request.Path.Value ?? "";
        string route = VaultPolicy.Classify(context.Request.Method, path);
        if (!config.ObserveDeniedEndpoints && route.StartsWith("denied:", StringComparison.Ordinal)) route = "unknown-or-forbidden";
        // Unknown raw paths may contain exfiltrated credentials. Log classifications only.
        string method = context.Request.Method is "GET" or "POST" or "PUT" or "DELETE" or "OPTIONS" or "HEAD" ? context.Request.Method : "OTHER";
        audit($"http:{method}:{route}");
        context.Response.Headers.CacheControl = "no-store";
        context.Response.Headers["X-Content-Type-Options"] = "nosniff";
        if (!IPAddress.IsLoopback(context.Connection.RemoteIpAddress ?? IPAddress.None) ||
            context.Request.Host.Host != "127.0.0.1" || !VaultPolicy.IsAllowedQuery(context.Request.Method, path, context.Request.QueryString.Value ?? "") ||
            DateTimeOffset.UtcNow >= identity.ExpiresAt.AddSeconds(-30) ||
            !VaultPolicy.IsAllowed(config.Allowlist, context.Request.Method, path))
        { context.Response.StatusCode = 403; return; }

        string supplied = context.Request.Headers.Authorization.ToString();
        bool isPublic = VaultPolicy.IsPublic(context.Request.Method, path);
        if (!isPublic && (!supplied.StartsWith("Bearer ", StringComparison.Ordinal) ||
            !CryptographicOperations.FixedTimeEquals(fakeDigest, SHA256.HashData(Encoding.UTF8.GetBytes(supplied[7..])))))
        { context.Response.StatusCode = 403; return; }
        lock (calls)
        {
            long now = Environment.TickCount64;
            while (calls.TryPeek(out long time) && now - time >= 60_000) calls.Dequeue();
            if (calls.Count >= 120) { context.Response.StatusCode = 429; return; }
            calls.Enqueue(now);
        }
        try
        {
            string upstreamUrl = VaultPolicy.Upstream(path, context.Request.QueryString.Value ?? "");
            using var request = new HttpRequestMessage(new HttpMethod(context.Request.Method), upstreamUrl);
            if (!isPublic) request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", identity.Token.Reveal());
            // Allowed POSTs have no caller-controlled body. No URL/host/header pass-through.
            if (context.Request.Method == "POST") request.Content = new StringContent("{}", Encoding.UTF8, "application/json");
            using var response = await http.SendAsync(request, context.RequestAborted);
            if (!response.IsSuccessStatusCode) { context.Response.StatusCode = 502; return; }
            byte[] body = await response.Content.ReadAsByteArrayAsync(context.RequestAborted);
            try
            {
                if (body.Length > 2 * 1024 * 1024 || identity.Token.OccursIn(body)) { context.Response.StatusCode = 502; return; }
                context.Response.StatusCode = (int)response.StatusCode;
                context.Response.ContentType = "application/json";
                await context.Response.Body.WriteAsync(body, context.RequestAborted);
            }
            finally { CryptographicOperations.ZeroMemory(body); }
        }
        catch (Exception ex) when (ex is HttpRequestException or IOException or OperationCanceledException)
        { if (!context.Response.HasStarted) context.Response.StatusCode = 502; }
    }
}
