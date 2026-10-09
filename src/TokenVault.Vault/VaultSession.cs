using System.Security.Cryptography.X509Certificates;
using TokenVault.Core;

namespace TokenVault.Vault;

// One game session: the HTTPS API boundary plus the connection broker, both inside this trusted process.
// The sandboxed game only ever receives Descriptor (fake token + public certificate + ports).
public sealed class VaultSession : IAsyncDisposable
{
    private readonly CancellationTokenSource lifetime;
    private readonly WebApplication app;
    private readonly Task networking;
    private readonly X509Certificate2 certificate;
    private readonly HttpClient http;
    private readonly AuditLog log;

    public SessionDescriptor Descriptor { get; }
    public Task Completion => networking;

    private VaultSession(CancellationTokenSource lifetime, WebApplication app, Task networking, X509Certificate2 certificate,
        HttpClient http, AuditLog log, SessionDescriptor descriptor)
    {
        this.lifetime = lifetime; this.app = app; this.networking = networking; this.certificate = certificate;
        this.http = http; this.log = log; Descriptor = descriptor;
    }

    public static async Task<VaultSession> StartAsync(Configuration config, MinecraftIdentity identity, string auditPath, CancellationToken stop)
    {
        DateTimeOffset expires = new[] { identity.ExpiresAt.AddMinutes(-1), DateTimeOffset.UtcNow.AddMinutes(config.SessionMinutes) }.Min();
        if (expires <= DateTimeOffset.UtcNow) throw new UserVisibleException("Sign-in expires too soon. Sign out and sign in again.");
        var lifetime = CancellationTokenSource.CreateLinkedTokenSource(stop);
        lifetime.CancelAfter(expires - DateTimeOffset.UtcNow);
        var cert = LocalCertificate.Create();
        var log = new AuditLog(auditPath);
        var http = MinecraftApi.CreateHttp();
        WebApplication? app = null;
        try
        {
            string fake = FakeToken.Create(identity.Profile, expires);
            app = new HttpsVault(config, identity, fake, cert, http, log.Write).Create();
            await app.StartAsync(lifetime.Token);
            var authenticator = new MojangConnectionAuthenticator(http, identity);
            var servers = new List<LocalServer>();
            var brokers = new List<Task>();
            foreach (var server in config.Servers)
            {
                var listener = ConnectionBroker.Listen();
                servers.Add(new LocalServer(server.Name, ((System.Net.IPEndPoint)listener.LocalEndpoint).Port));
                brokers.Add(new ConnectionBroker(server, identity.Profile, authenticator, log.Write).RunAsync(listener, lifetime.Token));
            }
            Task networking = Task.WhenAll(brokers);
            var descriptor = new SessionDescriptor(identity.Profile, fake, Convert.ToBase64String(cert.Export(X509ContentType.Cert)),
                config.HttpsPort, servers, config.MinecraftVersion, expires);
            log.Write("session:started");
            return new VaultSession(lifetime, app, networking, cert, http, log, descriptor);
        }
        catch
        {
            lifetime.Cancel();
            if (app is not null) await app.DisposeAsync();
            http.Dispose(); log.Dispose(); cert.Dispose(); lifetime.Dispose();
            throw;
        }
    }

    // Closes the API listener and every broker connection. No authenticated connection outlives the session.
    public async ValueTask DisposeAsync()
    {
        lifetime.Cancel();
        await app.StopAsync(CancellationToken.None);
        try { await networking; } catch (OperationCanceledException) { } catch (System.Net.Sockets.SocketException) { }
        await app.DisposeAsync();
        log.Write("session:closed");
        http.Dispose(); log.Dispose(); certificate.Dispose(); lifetime.Dispose();
    }
}
