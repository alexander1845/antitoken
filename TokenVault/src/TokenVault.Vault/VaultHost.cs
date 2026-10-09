using System.Runtime.Versioning;
using System.Security.Cryptography.X509Certificates;
using TokenVault.Core;

namespace TokenVault.Vault;

[SupportedOSPlatform("windows")]
public static class VaultHost
{
    public static async Task RunAsync(Configuration config, MinecraftIdentity identity, CancellationToken stop)
    {
        DateTimeOffset expires = new[] { identity.ExpiresAt.AddMinutes(-1), DateTimeOffset.UtcNow.AddMinutes(config.SessionMinutes) }.Min();
        if (expires <= DateTimeOffset.UtcNow) throw new InvalidOperationException("Token expires too soon.");
        using var lifetime = CancellationTokenSource.CreateLinkedTokenSource(stop);
        lifetime.CancelAfter(expires - DateTimeOffset.UtcNow);
        using var cert = LocalCertificate.Create();
        string fake = FakeToken.Create(identity.Profile, expires);
        var descriptor = new SessionDescriptor(identity.Profile, fake, Convert.ToBase64String(cert.Export(X509ContentType.Cert)),
            config.HttpsPort, config.GamePort, config.MinecraftVersion, expires);
        using var log = new AuditLog(Path.Combine(Configuration.Expand(config.DataDirectory), "requests.log"));
        using var http = MinecraftApi.CreateHttp();
        var api = new HttpsVault(config, identity, fake, cert, http, log.Write);
        await using var app = api.Create();
        await app.StartAsync(lifetime.Token);
        var broker = new ConnectionBroker(config, identity.Profile, new MojangConnectionAuthenticator(http, identity), log.Write);
        Task networking = broker.RunAsync(lifetime.Token);
        Task handoff = DescriptorPipe.RunAsync(config, descriptor, lifetime.Token);
        Console.WriteLine($"Vault ready for {identity.Profile.Name}; local server 127.0.0.1:{config.GamePort}. Expires {expires:O}.");
        Console.WriteLine("Start the launcher under the gaming account. Ctrl+C locks the vault and closes game connections.");
        try
        {
            Task completed = await Task.WhenAny(networking, handoff, Task.Delay(Timeout.Infinite, lifetime.Token));
            await completed;
        }
        catch (OperationCanceledException) when (lifetime.IsCancellationRequested) { }
        finally
        {
            lifetime.Cancel();
            await app.StopAsync(CancellationToken.None);
            try { await Task.WhenAll(networking, handoff); } catch (OperationCanceledException) { }
        }
    }
}
