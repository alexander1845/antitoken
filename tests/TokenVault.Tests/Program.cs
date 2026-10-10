using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using TokenVault.Core;
using TokenVault.Launcher;
using TokenVault.Packs;
using TokenVault.Vault;
using Microsoft.Identity.Client;

const int RoundTrips = 500; // small-packet round trips timed through the broker relay

if (args.Length == 2 && args[0] == "--probe-fixture")
{
    await ProbeFixture(args[1]);
    return 0;
}
if (args.Length == 2 && args[0] == "--resolve-fixture")
{
    var config = new Configuration { MinecraftDirectory = args[1], GameDirectory = args[1], ModsDirectory = Path.Combine(args[1], "mods") };
    var descriptor = new SessionDescriptor(Profile(), FakeToken.Create(Profile(), DateTimeOffset.UtcNow.AddHours(1)), "", 25599, [], "26.1.2", DateTimeOffset.UtcNow.AddHours(1));
    string temp = Path.Combine(Path.GetTempPath(), "vault-resolve-test-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(temp);
    try
    {
        var launch = InstalledVersion.Resolve(config, descriptor, temp);
        Check(launch.MainClass == "net.fabricmc.loader.impl.launch.knot.KnotClient", "Wrong Fabric entry point.");
        Check(launch.GameArguments.Contains(descriptor.FakeToken), "Missing fake token.");
        Check(!launch.JvmArguments.Concat(launch.GameArguments).Any(a => a.Contains("${", StringComparison.Ordinal)), "Unresolved template variable.");
        Console.WriteLine("PASS exact 26.1.2/Fabric installed-profile resolution (not a game launch)");
    }
    finally { Directory.Delete(temp, true); }
    return 0;
}

var tests = new (string Name, Func<Task> Run)[]
{
    ("packet framing, compression bounds and malformed VarInts", PacketTests),
    ("Minecraft signed SHA-1 and continuous AES-CFB8", CryptoTests),
    ("fake JWT uniqueness and refresh-only cache serialization", TokenTests),
    ("envelope encryption: AES-256-GCM, header/context binding, tamper and key checks", EnvelopeTests),
    ("OAuth loopback rejects wrong state and requires PKCE", OAuthCallbackTests),
    ("API deny ceiling, TLS, token substitution and response non-disclosure", HttpTests),
    ("owned online login, Fabric query, compression and encrypted relay", BrokerTests),
    ("offline upstream refusal before gameplay", OfflineTests),
    ("sandbox folder policy, command-line quoting and Java truststore format", SandboxTests),
    ("server list file, server addresses, pack detection and pack path safety", PackTests),
    ("join approval and one connection at a time", ApprovalTests),
    ("broker hardening: game-only connections, join deadline, shared reconnect limit, disconnect", BrokerHardeningTests),
    ("API: wrong-token guesses rate-limited, chat signing can be turned off", ApiHardeningTests),
    ("batched AES-CFB8 matches the byte-by-byte definition", Cfb8BatchTests),
    ("pack import: game-folder allowlist, credential filter, versions and loaders", PackImportTests),
    ("updater: signed manifest, rollback and tamper refusal, in-place install", UpdaterTests),
    ("usage statistics: fixed vocabulary, project keys only", TelemetryTests),
    ("Modrinth: compatible versions, dependencies, checksums, CDN only", ModrinthTests)
};
int failures = 0;
foreach (var test in tests)
{
    try { await test.Run(); Console.WriteLine("PASS " + test.Name); }
    catch (Exception ex) { failures++; Console.Error.WriteLine("FAIL " + test.Name + ": " + ex); }
}
Console.WriteLine($"{tests.Length - failures}/{tests.Length} test groups passed. Real Microsoft/Mojang login and Windows isolation are separate acceptance gates.");
return failures == 0 ? 0 : 1;

static void Check(bool condition, string message) { if (!condition) throw new Exception(message); }
static async Task Throws<T>(Func<Task> action) where T : Exception
{
    try { await action(); } catch (T) { return; }
    throw new Exception("Expected " + typeof(T).Name);
}
static PlayerProfile Profile() => new("0123456789abcdef0123456789abcdef", "VaultTester");
static int Port() { var l = new TcpListener(IPAddress.Loopback, 0); l.Start(); int p = ((IPEndPoint)l.LocalEndpoint).Port; l.Stop(); return p; }

static async Task PacketTests()
{
    foreach (int threshold in new[] { -1, 0, 256 })
    foreach (int length in new[] { 1, 128, 1024, 65537 })
    {
        byte[] payload = RandomNumberGenerator.GetBytes(length);
        using var stream = new MemoryStream();
        await PacketIO.WriteAsync(stream, payload, threshold, default); stream.Position = 0;
        Check((await PacketIO.ReadAsync(stream, threshold, default)).SequenceEqual(payload), "Frame roundtrip mismatch.");
    }
    foreach (byte[] invalid in new[] { new byte[] { 0 }, new byte[] { 255, 255, 255, 255, 127 }, new byte[] { 128, 128, 128, 128, 128 } })
        await Throws<InvalidDataException>(() => PacketIO.ReadAsync(new MemoryStream(invalid), -1, default));
    await Throws<EndOfStreamException>(() => PacketIO.ReadAsync(new MemoryStream([5, 0, 1]), -1, default));
    // A compressed frame claiming a huge output is rejected before allocation/decompression.
    using var body = new MemoryStream(); PacketIO.WriteVarInt(body, PacketIO.MaxPacket + 1); body.WriteByte(1);
    using var framed = new MemoryStream(); PacketIO.WriteVarInt(framed, (int)body.Length); body.WriteTo(framed); framed.Position = 0;
    await Throws<InvalidDataException>(() => PacketIO.ReadAsync(framed, 256, default));
}

static async Task CryptoTests()
{
    Check(MinecraftCrypto.ServerHash("Notch", [], []) == "4ed1f46bbe04bc756bcb17c0c7ce3e4632f06a48", "Positive signed SHA-1 mismatch.");
    Check(MinecraftCrypto.ServerHash("jeb_", [], []) == "-7c9d5b0044c130109a5d7b5fb5c317c02b4e28c1", "Negative signed SHA-1 mismatch.");
    byte[] key = Convert.FromHexString("000102030405060708090a0b0c0d0e0f");
    byte[] plain = Enumerable.Range(0, 64).Select(n => (byte)n).ToArray();
    using var bytes = new MemoryStream();
    using (var cipher = new CipherStream(bytes, key))
    {
        await cipher.WriteAsync(plain.AsMemory(0, 1));
        await cipher.WriteAsync(plain.AsMemory(1, 19));
        await cipher.WriteAsync(plain.AsMemory(20));
    }
    // Independently generated with OpenSSL/Python cryptography, AES-128-CFB8, IV=key.
    string expected = "0a22f796e1b93e9032cff804838adfc3a5e4b3ffdd47108575533e672ef5d8ef4929ef289ace5bca4e6d3ae9a7c1c02d6808e094e196bdaf5a6fe1f0f413cacd";
    Check(Convert.ToHexString(bytes.ToArray()).ToLowerInvariant() == expected, "CFB8 fixture mismatch.");
    bytes.Position = 0;
    using var decrypt = new CipherStream(bytes, key); byte[] restored = new byte[64];
    await decrypt.ReadExactlyAsync(restored.AsMemory(0, 7)); await decrypt.ReadExactlyAsync(restored.AsMemory(7));
    Check(restored.SequenceEqual(plain), "Continuous CFB8 decryption mismatch.");
}

static Task EnvelopeTests()
{
    // Unauthenticated test wrap (XOR pad): any change to the wrapped key yields a different DEK, which GCM must catch.
    var wrap = new XorWrap(7);
    byte[] secret = Encoding.UTF8.GetBytes("refresh-canary " + new string('x', 300));
    byte[] a = Envelope.Seal(secret, "ctx|S-1-5-21-1", wrap), b = Envelope.Seal(secret, "ctx|S-1-5-21-1", wrap);
    Check(Envelope.IsEnvelope(a) && a.AsSpan().IndexOf("refresh-canary"u8) < 0, "Plaintext visible in envelope.");
    Check(!a.SequenceEqual(b), "Two seals of the same data must differ (fresh DEK and nonce).");
    Check(Envelope.Open(a, "ctx|S-1-5-21-1", id => id == 7 ? wrap : null).SequenceEqual(secret), "Envelope roundtrip failed.");
    // Every single-byte change anywhere (magic, version, wrap id, length, wrapped key, nonce, ciphertext, tag) is refused.
    for (int i = 0; i < a.Length; i++)
    {
        byte[] tampered = a.ToArray(); tampered[i] ^= 0x01;
        bool opened = false;
        try { Envelope.Open(tampered, "ctx|S-1-5-21-1", id => id == 7 ? wrap : null); opened = true; }
        catch (CryptographicException) { }
        catch (ArgumentException) { } // a corrupted length can make the layout invalid
        Check(!opened, $"Tampered byte {i} was accepted.");
    }
    Check(ThrowsCrypto(() => Envelope.Open(a, "ctx|S-1-5-21-2", id => wrap)), "Envelope opened under another user's context.");
    Check(ThrowsCrypto(() => Envelope.Open(a, "ctx|S-1-5-21-1", id => null)), "Envelope opened without its key wrap.");
    Check(ThrowsCrypto(() => Envelope.Open(a[..20], "ctx|S-1-5-21-1", id => wrap)), "Truncated envelope accepted.");
    Check(Envelope.Open(Envelope.Seal([], "c", wrap), "c", _ => wrap).Length == 0, "Empty plaintext roundtrip failed.");
    WindowsKeyWrapTests(secret);
    return Task.CompletedTask;
}

static void WindowsKeyWrapTests(byte[] secret)
{
    if (!OperatingSystem.IsWindows()) return;
    var dpapi = new DpapiKeyWrap("TokenVault.Tests"u8.ToArray());
    Check(Envelope.Open(Envelope.Seal(secret, "c", dpapi), "c", id => id == DpapiKeyWrap.WrapId ? dpapi : null).SequenceEqual(secret), "DPAPI envelope roundtrip failed.");
    // TPM-bound wrapping only where the runner has a TPM; CI runners usually don't, which exercises the fallback.
    Console.WriteLine(TpmKeyWrap.TryOpen(dpapi, create: false) is { } tpm
        ? (Envelope.Open(Envelope.Seal(secret, "c", tpm), "c", _ => tpm).SequenceEqual(secret) ? "     (TPM-bound wrap verified)" : throw new Exception("TPM roundtrip failed."))
        : "     (no existing TPM key on this machine; DPAPI path verified)");
}

static bool ThrowsCrypto(Action action)
{
    try { action(); return false; } catch (CryptographicException) { return true; }
}

static async Task TokenTests()
{
    var a = FakeToken.Create(Profile(), DateTimeOffset.UtcNow.AddHours(1));
    var b = FakeToken.Create(Profile(), DateTimeOffset.UtcNow.AddHours(1));
    Check(a != b && a.Split('.').Length == 3, "Fake must be a unique JWT.");
    string part = a.Split('.')[1].Replace('-', '+').Replace('_', '/');
    using var payload = JsonDocument.Parse(Convert.FromBase64String(part.PadRight((part.Length + 3) / 4 * 4, '=')));
    Check(payload.RootElement.GetProperty("exp").GetInt64() > DateTimeOffset.UtcNow.ToUnixTimeSeconds(), "Fake expired.");
    byte[] filtered = RefreshCacheFilter.Filter(Encoding.UTF8.GetBytes("{\"AccessToken\":{\"x\":{\"secret\":\"access-canary\"}},\"IdToken\":{\"x\":{\"secret\":\"id-canary\"}},\"RefreshToken\":{\"x\":{\"secret\":\"refresh-canary\"}},\"Account\":{},\"AppMetadata\":{}}"));
    string result = Encoding.UTF8.GetString(filtered);
    Check(!result.Contains("access-canary") && !result.Contains("id-canary") && result.Contains("refresh-canary"), "Cache leaked non-refresh credential.");
    try { RefreshCacheFilter.Filter("{\"FutureSecret\":{}}"u8.ToArray()); throw new Exception("Unknown cache schema accepted."); }
    catch (InvalidDataException) { }
    Check(!VaultPolicy.IsAllowed(["POST /session/minecraft/join", "*"], "POST", "/session/minecraft/join"), "Configuration expanded ceiling.");
    var msal = Microsoft.Identity.Client.PublicClientApplicationBuilder.Create("00000000-0000-0000-0000-000000000001").Build();
    bool schemaChecked = false;
    msal.UserTokenCache.SetBeforeAccess(notification =>
    {
        _ = RefreshCacheFilter.Filter(notification.TokenCache.SerializeMsalV3());
        schemaChecked = true;
    });
    await msal.GetAccountsAsync();
    Check(schemaChecked, "Actual MSAL cache schema was not checked.");
    Check(VaultPolicy.SanitizePath("/exfil/" + a).Contains("[redacted]"), "Fake leaked into audit path.");
    Check(VaultPolicy.Classify("GET", "/services/privacy/blocklist") == "routine:blocklist" && VaultPolicy.Classify("POST", "/services/events") == "routine:telemetry", "Routine game requests reported as blocked.");
    Check(!VaultPolicy.IsAllowed(VaultPolicy.DefaultAllowlist, "GET", "/services/privacy/blocklist") && !VaultPolicy.IsAllowed(VaultPolicy.DefaultAllowlist, "POST", "/services/events"), "A routine request was let through.");
    Check(VaultPolicy.Classify("PUT", "/services/minecraft/profile/name/x").StartsWith("denied:"), "An account change was classed as routine.");
    Check(!InstalledVersion.Allowed(JsonNode.Parse("[{\"action\":\"allow\",\"os\":{\"name\":\"linux\"}}]")), "Wrong OS library accepted.");
}

static async Task OAuthCallbackTests()
{
    int port = Port(); var callback = new Uri($"http://127.0.0.1:{port}/");
    string state = "synthetic-state-12345678901234567890";
    var auth = new Uri("https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize?state=" + state + "&code_challenge_method=S256&code_challenge=" + new string('a', 43));
    using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
    using var http = new HttpClient(new HttpClientHandler { UseProxy = false });
    var ui = new SystemBrowserUi(port, async _ =>
    {
        using var wrong = await http.GetAsync(callback + "?code=canary&state=wrong", timeout.Token);
        Check(wrong.StatusCode == HttpStatusCode.Forbidden, "Wrong OAuth state accepted.");
        using var right = await http.PostAsync(callback, new FormUrlEncodedContent(new Dictionary<string, string> { ["state"] = state, ["code"] = "synthetic-auth-code" }), timeout.Token);
        Check(right.IsSuccessStatusCode, "Valid synthetic callback refused.");
    });
    Uri returned = await ui.AcquireAuthorizationCodeAsync(auth, callback, timeout.Token);
    Check(returned.Query.Contains("synthetic-auth-code") && returned.Query.Contains(state), "MSAL callback data lost.");
    await Throws<UserVisibleException>(() => ui.AcquireAuthorizationCodeAsync(new Uri("https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize"), callback, timeout.Token));
}

static async Task HttpTests()
{
    var config = new Configuration { HttpsPort = Port() };
    using var identity = new MinecraftIdentity(new SecretValue("real-access-canary-never-export"), Profile(), DateTimeOffset.UtcNow.AddHours(1));
    string fake = FakeToken.Create(Profile(), identity.ExpiresAt);
    using var cert = LocalCertificate.Create();
    var handler = new MockApi(); using var upstream = new HttpClient(handler);
    var logs = new List<string>();
    await using var app = new HttpsVault(config, identity, fake, cert, upstream, logs.Add).Create();
    await app.StartAsync();
    using var localHandler = new HttpClientHandler
    {
        UseProxy = false,
        ServerCertificateCustomValidationCallback = (_, peer, _, _) => peer?.GetCertHashString() == cert.GetCertHashString()
    };
    using var client = new HttpClient(localHandler) { BaseAddress = new Uri($"https://127.0.0.1:{config.HttpsPort}") };
    client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", fake);
    try
    {
        foreach (var target in new[]
        {
            ("POST", "/session/minecraft/join"), ("POST", "/session/session/minecraft/join"),
            ("PUT", "/services/minecraft/profile/name/evil"), ("POST", "/services/minecraft/profile/skins"),
            ("GET", "/services/player/attributes?url=https://attacker.invalid"), ("GET", "/services/player/attributes/")
        })
        {
            using var req = new HttpRequestMessage(new HttpMethod(target.Item1), target.Item2);
            req.Content = new StringContent("{\"serverId\":\"attacker-selected-hash\",\"accessToken\":\"" + fake + "\"}");
            using var response = await client.SendAsync(req);
            Check(response.StatusCode == HttpStatusCode.Forbidden, "Forbidden operation accepted: " + target.Item2);
        }
        Check(handler.Calls == 0, "Denied request reached upstream.");
        string content = await client.GetStringAsync("/services/player/attributes");
        Check(handler.Authorization == "Bearer real-access-canary-never-export", "Real bearer not substituted upstream.");
        Check(!content.Contains("real-access") && !content.Contains(fake), "Credential in downstream response.");
        using var wrong = new HttpRequestMessage(HttpMethod.Get, "/services/player/attributes");
        wrong.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "wrong-fake");
        using var wrongReply = await client.SendAsync(wrong);
        Check(wrongReply.StatusCode == HttpStatusCode.Forbidden, "Wrong fake accepted.");
        handler.Body = "{\"leak\":\"real-access-canary-never-export\"}";
        using var leak = await client.GetAsync("/services/player/attributes");
        Check(leak.StatusCode == HttpStatusCode.BadGateway && !(await leak.Content.ReadAsStringAsync()).Contains("real-access"), "Response secret guard failed.");
        handler.Status = HttpStatusCode.Redirect;
        using var redirect = await client.GetAsync("/services/player/attributes");
        Check(redirect.StatusCode == HttpStatusCode.BadGateway && redirect.Headers.Location is null, "Redirect escaped vault.");
        Check(logs.All(x => !x.Contains(fake) && !x.Contains("real-access")), "Credentials logged.");
    }
    finally { await app.StopAsync(); }
}

static async Task BrokerTests()
{
    using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15)); var ct = deadline.Token;
    var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start();
    int remotePort = ((IPEndPoint)listener.LocalEndpoint).Port;
    var acceptedHash = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
    var auth = new MockAuthenticator(acceptedHash);
    using var rsa = RSA.Create(1024);
    byte[] pub = rsa.ExportSubjectPublicKeyInfo(); byte[] verify = RandomNumberGenerator.GetBytes(4);
    Task server = Task.Run(async () =>
    {
        using var remote = await listener.AcceptTcpClientAsync(ct); remote.NoDelay = true; Stream raw = remote.GetStream();
        var handshake = await PacketIO.ReadAsync(raw, -1, ct); int o = 0;
        Check(PacketIO.ReadVarInt(handshake, ref o) == 0 && PacketIO.ReadVarInt(handshake, ref o) == 775, "Wrong upstream protocol.");
        Check(PacketIO.ReadString(handshake, ref o) == "127.0.0.1", "Untrusted game destination escaped.");
        Check((await PacketIO.ReadAsync(raw, -1, ct)).SequenceEqual(PacketIO.LoginStart(Profile())), "Wrong upstream identity.");
        await PacketIO.WriteAsync(raw, PacketIO.Packet(1, s => { PacketIO.WriteString(s, ""); PacketIO.WriteBytes(s, pub); PacketIO.WriteBytes(s, verify); s.WriteByte(1); }), -1, ct);
        var response = await PacketIO.ReadAsync(raw, -1, ct); o = 0;
        Check(PacketIO.ReadVarInt(response, ref o) == 1, "Missing encryption response.");
        byte[] secret = rsa.Decrypt(PacketIO.ReadBytes(response, ref o, 4096), RSAEncryptionPadding.Pkcs1);
        Check(rsa.Decrypt(PacketIO.ReadBytes(response, ref o, 4096), RSAEncryptionPadding.Pkcs1).SequenceEqual(verify), "Wrong server challenge.");
        Check(await acceptedHash.Task.WaitAsync(ct) == MinecraftCrypto.ServerHash("", secret, pub), "Hash not bound to owned connection.");
        Check(auth.Calls == 1, "Extra authentication capability used.");
        using var encrypted = new CipherStream(raw, secret); CryptographicOperations.ZeroMemory(secret);
        await PacketIO.WriteAsync(encrypted, PacketIO.Packet(3, s => PacketIO.WriteVarInt(s, 256)), -1, ct);
        await PacketIO.WriteAsync(encrypted, PacketIO.Packet(4, s => { PacketIO.WriteVarInt(s, 7); PacketIO.WriteString(s, "fabric:test"); }), 256, ct);
        var pluginReply = await PacketIO.ReadAsync(encrypted, 256, ct);
        Check(pluginReply.SequenceEqual(new byte[] { 2, 7, 0 }), "Fabric plugin response not forwarded.");
        await PacketIO.WriteAsync(encrypted, PacketIO.Packet(2, s => { s.Write(Convert.FromHexString(Profile().Id)); PacketIO.WriteString(s, Profile().Name); PacketIO.WriteVarInt(s, 0); }), 256, ct);
        Check((await PacketIO.ReadAsync(encrypted, 256, ct)).SequenceEqual(new byte[] { 3 }), "Missing login ACK.");
        byte[] application = new byte[100_000]; await encrypted.ReadExactlyAsync(application, ct);
        Check(application.All(b => b == 42), "Game relay corrupted.");
        await encrypted.WriteAsync(application, ct);
        byte[] small = new byte[24];
        for (int i = 0; i < RoundTrips; i++) { await encrypted.ReadExactlyAsync(small, ct); await encrypted.WriteAsync(small, ct); }
    }, ct);
    var local = new TcpListener(IPAddress.Loopback, 0); local.Start();
    using var game = new TcpClient { NoDelay = true }; await game.ConnectAsync(IPAddress.Loopback, ((IPEndPoint)local.LocalEndpoint).Port, ct);
    using var brokerSocket = await local.AcceptTcpClientAsync(ct); brokerSocket.NoDelay = true; // as the real broker does
    var broker = new ConnectionBroker(new ServerEntry("test", "127.0.0.1", remotePort), Profile(), auth, _ => { });
    Task relay = broker.HandleAsync(brokerSocket.GetStream(), ct);
    try
    {
        Stream stream = game.GetStream();
        await PacketIO.WriteAsync(stream, PacketIO.Handshake("attacker.invalid", 1234, 2), -1, ct);
        await PacketIO.WriteAsync(stream, PacketIO.LoginStart(Profile()), -1, ct);
        byte[] compression = await PacketIO.ReadAsync(stream, -1, ct);
        Check(compression[0] == 3, "JVM was exposed to upstream encryption request.");
        byte[] plugin = await PacketIO.ReadAsync(stream, 256, ct); Check(plugin[0] == 4, "Plugin query missing.");
        await PacketIO.WriteAsync(stream, [2, 7, 0], 256, ct);
        Check((await PacketIO.ReadAsync(stream, 256, ct))[0] == 2, "Login success missing.");
        await PacketIO.WriteAsync(stream, [3], 256, ct);
        byte[] payload = Enumerable.Repeat((byte)42, 100_000).ToArray(); await stream.WriteAsync(payload, ct);
        byte[] echo = new byte[payload.Length]; await stream.ReadExactlyAsync(echo, ct);
        Check(echo.SequenceEqual(payload), "Encrypted bidirectional stream failed.");
        // Ping: small packets through the whole relay (plain to the game, encrypted to the server) against the same
        // round trips over a direct connection. Only the difference is Token Vault's doing.
        var relayed = await RoundTripMicrosecondsAsync(stream, ct);
        var direct = await DirectRoundTripMicrosecondsAsync(ct);
        double added = relayed[RoundTrips / 2] - direct[RoundTrips / 2], addedP99 = relayed[RoundTrips * 99 / 100] - direct[RoundTrips * 99 / 100];
        Console.WriteLine($"     (relay adds {Math.Max(0, added):0} µs median, {Math.Max(0, addedP99):0} µs at the 99th percentile, per round trip)");
        Check(added < 2000, $"The relay adds {added:0} µs to a round trip; it should be well under a millisecond.");
        game.Close(); await server; await relay;
        await ServerListPingTests(ct);
    }
    finally { listener.Stop(); local.Stop(); deadline.Cancel(); }
}

// The multiplayer screen's ping must be the server's: the pong comes from upstream, not from Token Vault.
static async Task ServerListPingTests(CancellationToken ct)
{
    var upstream = new TcpListener(IPAddress.Loopback, 0); upstream.Start();
    var local = new TcpListener(IPAddress.Loopback, 0); local.Start();
    try
    {
        Task server = Task.Run(async () =>
        {
            using var client = await upstream.AcceptTcpClientAsync(ct); var s = client.GetStream();
            await PacketIO.ReadAsync(s, -1, ct); await PacketIO.ReadAsync(s, -1, ct); // handshake, status request
            await PacketIO.WriteAsync(s, PacketIO.Packet(0, w => PacketIO.WriteString(w, "{\"description\":{\"text\":\"real server\"}}")), -1, ct);
            byte[] ping = await PacketIO.ReadAsync(s, -1, ct);
            ping[8] ^= 0xFF; // a pong only the server could have sent
            await PacketIO.WriteAsync(s, ping, -1, ct);
        }, ct);
        using var game = new TcpClient { NoDelay = true }; await game.ConnectAsync(IPAddress.Loopback, ((IPEndPoint)local.LocalEndpoint).Port, ct);
        using var brokerSocket = await local.AcceptTcpClientAsync(ct);
        var broker = new ConnectionBroker(new ServerEntry("test", "127.0.0.1", ((IPEndPoint)upstream.LocalEndpoint).Port), Profile(),
            new MockAuthenticator(new TaskCompletionSource<string>()), _ => { });
        Task handling = broker.HandleAsync(brokerSocket.GetStream(), ct);
        Stream stream = game.GetStream();
        await PacketIO.WriteAsync(stream, PacketIO.Handshake("localhost", 1, 1), -1, ct);
        await PacketIO.WriteAsync(stream, [0], -1, ct);
        Check(Encoding.UTF8.GetString(await PacketIO.ReadAsync(stream, -1, ct)).Contains("real server"), "Server list didn't show the server's own status.");
        byte[] ping = [1, 1, 2, 3, 4, 5, 6, 7, 8];
        await PacketIO.WriteAsync(stream, ping, -1, ct);
        byte[] pong = await PacketIO.ReadAsync(stream, -1, ct);
        Check(pong.Length == 9 && pong[8] == (ping[8] ^ 0xFF), "Server-list ping was answered locally instead of by the server.");
        await server; await handling;
    }
    finally { upstream.Stop(); local.Stop(); }
}

static async Task<double[]> RoundTripMicrosecondsAsync(Stream stream, CancellationToken ct)
{
    byte[] small = Enumerable.Range(0, 24).Select(i => (byte)i).ToArray(), back = new byte[small.Length];
    var times = new double[RoundTrips];
    for (int i = 0; i < RoundTrips; i++)
    {
        long start = System.Diagnostics.Stopwatch.GetTimestamp();
        await stream.WriteAsync(small, ct);
        await stream.ReadExactlyAsync(back, ct);
        times[i] = System.Diagnostics.Stopwatch.GetElapsedTime(start).TotalMicroseconds;
        Check(back.SequenceEqual(small), "Relay changed a small packet.");
    }
    Array.Sort(times);
    return times;
}

static async Task<double[]> DirectRoundTripMicrosecondsAsync(CancellationToken ct)
{
    var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start();
    try
    {
        using var client = new TcpClient { NoDelay = true };
        await client.ConnectAsync(IPAddress.Loopback, ((IPEndPoint)listener.LocalEndpoint).Port, ct);
        using var server = await listener.AcceptTcpClientAsync(ct); server.NoDelay = true;
        Task echo = Task.Run(async () =>
        {
            byte[] small = new byte[24]; var s = server.GetStream();
            for (int i = 0; i < RoundTrips; i++) { await s.ReadExactlyAsync(small, ct); await s.WriteAsync(small, ct); }
        }, ct);
        var times = await RoundTripMicrosecondsAsync(client.GetStream(), ct);
        await echo;
        return times;
    }
    finally { listener.Stop(); }
}

static async Task OfflineTests()
{
    using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5)); var ct = timeout.Token;
    var remote = new TcpListener(IPAddress.Loopback, 0); remote.Start();
    var local = new TcpListener(IPAddress.Loopback, 0); local.Start();
    using var game = new TcpClient(); await game.ConnectAsync(IPAddress.Loopback, ((IPEndPoint)local.LocalEndpoint).Port, ct);
    using var accepted = await local.AcceptTcpClientAsync(ct);
    var auth = new MockAuthenticator(new TaskCompletionSource<string>());
    var broker = new ConnectionBroker(new ServerEntry("test", "127.0.0.1", ((IPEndPoint)remote.LocalEndpoint).Port), Profile(), auth, _ => { });
    Task handling = broker.HandleAsync(accepted.GetStream(), ct);
    try
    {
        await PacketIO.WriteAsync(game.GetStream(), PacketIO.Handshake("localhost", 1, 2), -1, ct);
        await PacketIO.WriteAsync(game.GetStream(), PacketIO.LoginStart(Profile()), -1, ct);
        using var server = await remote.AcceptTcpClientAsync(ct);
        await PacketIO.ReadAsync(server.GetStream(), -1, ct); await PacketIO.ReadAsync(server.GetStream(), -1, ct);
        await PacketIO.WriteAsync(server.GetStream(), PacketIO.Packet(2), -1, ct);
        await Throws<InvalidDataException>(() => handling);
        Check(auth.Calls == 0, "Offline server obtained authentication.");
        byte[] reason = await PacketIO.ReadAsync(game.GetStream(), -1, ct);
        Check(reason.Length > 1 && reason[0] == 0, "The game was not told why the join failed.");
    }
    finally { remote.Stop(); local.Stop(); }
}

static Task SandboxTests()
{
    // Folders that hold sign-in data (or contain such folders) are never shared with the game sandbox.
    var c = new Configuration { MinecraftDirectory = Path.Combine(Path.GetTempPath(), "mc-root"), GameDirectory = Path.Combine(Path.GetTempPath(), "mc-root") };
    string root = Configuration.Expand(c.MinecraftDirectory);
    foreach (string bad in new[] { root, Path.GetDirectoryName(root)!, AppPaths.Data, AppPaths.Root,
                 Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), Path.Combine(AppPaths.Data, "sub") })
        try { SandboxPolicy.CheckRead(c, bad); throw new Exception("Sandbox may access protected folder: " + bad); }
        catch (UserVisibleException) { }
    string libraries = Path.Combine(root, "libraries");
    SandboxPolicy.CheckRead(c, libraries);
    SandboxPolicy.CheckRead(c, Path.Combine(AppPaths.Root, "Instance"));
    try { SandboxPolicy.CheckWrite(c, root, [libraries]); throw new Exception(".minecraft root accepted as writable instance."); }
    catch (UserVisibleException) { }
    try { SandboxPolicy.CheckWrite(c, Path.Combine(libraries, "x"), [libraries]); throw new Exception("Writable folder inside shared libraries accepted."); }
    catch (UserVisibleException) { }
    SandboxPolicy.CheckWrite(c, Path.Combine(AppPaths.Root, "Instance"), [libraries]);
    Check(SandboxPolicy.IsWithin("C:/a/bc", "C:/a/b") == false && SandboxPolicy.IsWithin("C:/a/b/c", "C:/a/b"), "Prefix confusion in IsWithin.");
    GameFolderRepairTests();

    // Arguments must reach java.exe exactly as given (CommandLineToArgvW rules).
    Check(WindowsCommandLine.Build("C:/j/java.exe", ["-Da=b", "two words", "", "q\"x", @"tail\", @"C:\dir with space\"]) ==
        """C:/j/java.exe -Da=b "two words" "" "q\"x" tail\ "C:\dir with space\\" """.TrimEnd(), "Windows argument quoting mismatch.");
    try { WindowsCommandLine.Build("java.exe", ["a\0b"]); throw new Exception("NUL accepted in argument."); } catch (InvalidDataException) { }

    // JKS: trusted-certificate entries only, verifiable keyed SHA-1 trailer.
    using var rsa = RSA.Create(2048);
    var req = new System.Security.Cryptography.X509Certificates.CertificateRequest("CN=test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(1));
    byte[] store = JavaTrustStore.Create([("tokenvault-loopback", cert.RawData), ("root-a", cert.RawData)], DateTimeOffset.UnixEpoch);
    byte[] data = store[..^20];
    using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA1);
    sha.AppendData(Encoding.BigEndianUnicode.GetBytes(JavaTrustStore.Password)); sha.AppendData("Mighty Aphrodite"u8); sha.AppendData(data);
    Check(store[^20..].SequenceEqual(sha.GetHashAndReset()), "JKS integrity digest mismatch.");
    Check(data[..12].SequenceEqual(new byte[] { 0xFE, 0xED, 0xFE, 0xED, 0, 0, 0, 2, 0, 0, 0, 2 }), "JKS header mismatch.");
    Check(data[12..16].SequenceEqual(new byte[] { 0, 0, 0, 2 }), "Entry is not a trusted-certificate entry.");
    Check(data.AsSpan().IndexOf(cert.RawData) > 0 && data.AsSpan().IndexOf("PRIVATE"u8) < 0, "Truststore content unexpected.");
    try { JavaTrustStore.Create([("Dup", cert.RawData)], DateTimeOffset.UnixEpoch); throw new Exception("Uppercase alias accepted."); }
    catch (ArgumentException) { }
    return Task.CompletedTask;
}

// A game folder an earlier build left open to other accounts is made private in place, keeping its contents; one with a
// link inside is refused rather than having permissions applied wherever the link points.
static void GameFolderRepairTests()
{
    if (!OperatingSystem.IsWindows()) return;
    var others = new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.AuthenticatedUserSid, null);
    string OpenFolder()
    {
        string path = Path.Combine(Path.GetTempPath(), "tv-gameroot-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path.Combine(path, "Instances", "a"));
        File.WriteAllText(Path.Combine(path, "Instances", "a", "world.dat"), "keep");
        var info = new DirectoryInfo(path);
        var acl = info.GetAccessControl();
        acl.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(others, System.Security.AccessControl.FileSystemRights.Modify,
            System.Security.AccessControl.InheritanceFlags.ContainerInherit | System.Security.AccessControl.InheritanceFlags.ObjectInherit,
            System.Security.AccessControl.PropagationFlags.None, System.Security.AccessControl.AccessControlType.Allow));
        info.SetAccessControl(acl);
        return path;
    }
    bool OthersCanReach(string path)
    {
        foreach (System.Security.AccessControl.FileSystemAccessRule rule in new FileInfo(path).GetAccessControl()
                     .GetAccessRules(true, true, typeof(System.Security.Principal.SecurityIdentifier)))
            if (rule.IdentityReference == others) return true;
        return false;
    }

    string open = OpenFolder(), linked = OpenFolder(), target = Path.Combine(Path.GetTempPath(), "tv-linktarget-" + Guid.NewGuid().ToString("N"));
    try
    {
        string world = Path.Combine(open, "Instances", "a", "world.dat");
        Check(OthersCanReach(world), "Test setup: folder isn't open to other accounts.");
        GameFolders.Secure(open, null);
        Check(new DirectoryInfo(open).GetAccessControl().AreAccessRulesProtected, "Open game folder wasn't made private.");
        Check(!OthersCanReach(world), "Other accounts can still change files inside a repaired game folder.");
        Check(File.ReadAllText(world) == "keep", "Repairing the game folder lost the player's files.");
        GameFolders.Secure(open, null); // already private: nothing to do

        Directory.CreateDirectory(target);
        using (var mklink = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "cmd.exe"),
                   $"/d /c mklink /J \"{Path.Combine(linked, "Instances", "link")}\" \"{target}\"") { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true })!)
            mklink.WaitForExit();
        Check(Directory.Exists(Path.Combine(linked, "Instances", "link")), "Test setup: junction wasn't created.");
        try { GameFolders.Secure(linked, null); throw new Exception("Game folder with a link inside was repaired."); }
        catch (UserVisibleException) { }
        Check(!new DirectoryInfo(linked).GetAccessControl().AreAccessRulesProtected, "Game folder with a link inside was changed.");
    }
    finally
    {
        try { Directory.Delete(Path.Combine(linked, "Instances", "link")); } catch (IOException) { }
        foreach (string dir in new[] { open, linked, target }) try { Directory.Delete(dir, recursive: true); } catch (IOException) { }
    }
}

static Task PackTests()
{
    // servers.dat: uncompressed NBT {servers: [{name, ip}]} pointing at local brokers.
    byte[] nbt = ServersFile.Create([new LocalServer("My Server", 50123)]);
    byte[] expected = [10, 0, 0, 9, 0, 7, .. "servers"u8, 10, 0, 0, 0, 1,
        8, 0, 4, .. "name"u8, 0, 9, .. "My Server"u8, 8, 0, 2, .. "ip"u8, 0, 15, .. "127.0.0.1:50123"u8, 0, 0];
    Check(nbt.SequenceEqual(expected), "servers.dat encoding mismatch.");
    Check(ServersFile.Create([new LocalServer("é", 1)]).AsSpan().IndexOf(new byte[] { 0, 2, 0xC3, 0xA9 }) > 0, "Modified UTF-8 mismatch.");

    var parsed = ServerEntry.Parse(" Play.Example.net:25566 ");
    Check(parsed.Host == "play.example.net" && parsed.Port == 25566, "Server address parse failed.");
    Check(ServerEntry.Parse("mc.example.org").Port == 25565, "Default port missing.");
    foreach (string bad in new[] { "", "a b", "host:99999", "host:-1", "user@host", "host/path", "[::1]:25565", "host:1:2" })
        try { ServerEntry.Parse(bad); throw new Exception("Bad server address accepted: " + bad); } catch (InvalidDataException) { }

    // Pack format detection from archive contents (no network).
    string dir = Path.Combine(Path.GetTempPath(), "vault-pack-test-" + Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(dir);
    try
    {
        string Zip(string name, params (string Path, string Text)[] files)
        {
            string file = Path.Combine(dir, name);
            using var zip = System.IO.Compression.ZipFile.Open(file, System.IO.Compression.ZipArchiveMode.Create);
            foreach (var (path, text) in files)
                using (var w = new StreamWriter(zip.CreateEntry(path).Open())) w.Write(text);
            return file;
        }
        (PackImporter.PackKind, string) DetectFile(string file) { using var s = PackSource.Open(file); return PackImporter.Detect(s); }
        Check(DetectFile(Zip("a.mrpack", ("modrinth.index.json", "{}"), ("overrides/config/x.txt", "x"))) == (PackImporter.PackKind.Modrinth, ""), "Modrinth not detected.");
        Check(DetectFile(Zip("b.zip", ("manifest.json", "{\"manifestType\":\"minecraftModpack\"}"))) == (PackImporter.PackKind.CurseForge, ""), "CurseForge not detected.");
        Check(DetectFile(Zip("c.zip", ("manifest.json", "{\"other\":1}"), ("Wrap/.minecraft/mods/a.jar", "j"))) == (PackImporter.PackKind.Loose, "Wrap/.minecraft/"), "Wrapped .minecraft not found.");
        Check(DetectFile(Zip("d.zip", ("My Pack/mmc-pack.json", "{}"), ("My Pack/instance.cfg", "name=x"))) == (PackImporter.PackKind.Prism, "My Pack/"), "Prism export not detected.");
        Check(DetectFile(Zip("e.zip", ("a.jar", "j"), ("sub/b.jar", "j"))).Item1 == PackImporter.PackKind.Loose, "Loose jars not detected.");

        // Unsafe names in packs are refused; credential files from other launchers are never copied.
        foreach (string bad in new[] { "../x", "a/../../x", "/abs", "C:/x", "a/CON", "a/b.", @"x\..\..\y" })
            try { SafeFiles.Under(dir, bad); throw new Exception("Unsafe pack path accepted: " + bad); } catch (UserVisibleException) { }
        Check(SafeFiles.Under(dir, "mods/a.jar") == Path.Combine(dir, "mods", "a.jar"), "Safe pack path rejected.");
        Check(SafeFiles.IsCredentialFile("x/launcher_accounts.json") && SafeFiles.IsCredentialFile("accounts.json") && !SafeFiles.IsCredentialFile("mods/a.jar"),
            "Credential file filter wrong.");
        foreach (string bad in new[] { "../x", "versions/../../x", "a//b" })
            try { GameInstaller.Under(dir, bad); throw new Exception("Unsafe install path accepted: " + bad); } catch (InvalidDataException) { }

        // Packs set up their instance for the Minecraft version and loader they declare.
        var forge = new Instance(); PackImporter.ApplyLoader(forge, "1.20.1", "forge", "47.2.0");
        Check(forge.MinecraftVersion == "1.20.1" && forge.Loader == "forge" && forge.LoaderVersion == "1.20.1-47.2.0", "Forge pack version not applied.");
        var neo = new Instance(); PackImporter.ApplyLoader(neo, "1.21.1", "neoforge", "21.1.77");
        Check(neo.LoaderVersion == "21.1.77" && neo.Loader == "neoforge", "NeoForge pack version not applied.");
        var plain = new Instance(); PackImporter.ApplyLoader(plain, "1.21.4", null, null);
        Check(plain.Loader == "vanilla" && plain.LoaderVersion is null, "Loader-less pack not vanilla.");
        try { PackImporter.ApplyLoader(new Instance(), "1.21.1", "liteloader", "1"); throw new Exception("Unknown loader accepted."); } catch (UserVisibleException) { }
        try { PackImporter.ApplyLoader(new Instance(), "../x", "fabric", "1"); throw new Exception("Bad version accepted."); } catch (UserVisibleException) { }
        Check(PackImporter.LoaderId("net.neoforged") == "neoforge" && PackImporter.LoaderId("quilt-loader") == "quilt" && PackImporter.LoaderId("x") is null, "Loader ids wrong.");
    }
    finally { Directory.Delete(dir, true); }
    return Task.CompletedTask;
}

static async Task ApprovalTests()
{
    using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10)); var ct = timeout.Token;
    var events = new List<string>();
    async Task<(byte[] Reply, Task Handling, MockAuthenticator Auth)> Attempt(JoinApproval? approve, BrokerGate? slot)
    {
        var local = new TcpListener(IPAddress.Loopback, 0); local.Start();
        var game = new TcpClient(); await game.ConnectAsync(IPAddress.Loopback, ((IPEndPoint)local.LocalEndpoint).Port, ct);
        var accepted = await local.AcceptTcpClientAsync(ct); local.Stop();
        var auth = new MockAuthenticator(new TaskCompletionSource<string>());
        // Port 9 (discard) on loopback: an approved join would try to connect here; a blocked one never does.
        var broker = new ConnectionBroker(new ServerEntry("Hypixel", "127.0.0.1", 9), Profile(), auth, events.Add, approve, slot);
        Task handling = broker.HandleAsync(accepted.GetStream(), ct);
        _ = handling.ContinueWith(_ => accepted.Dispose(), TaskScheduler.Default); // the game sees the socket close
        await PacketIO.WriteAsync(game.GetStream(), PacketIO.Handshake("mc.hypixel.net", 25565, 2), -1, ct);
        try { await PacketIO.WriteAsync(game.GetStream(), PacketIO.LoginStart(Profile()), -1, ct); }
        catch (IOException) { } // a refused connection may already be closed
        byte[] reply = [];
        try { reply = await PacketIO.ReadAsync(game.GetStream(), -1, ct); } catch (Exception ex) when (ex is IOException or EndOfStreamException) { }
        return (reply, handling, auth);
    }

    // A join the player didn't approve gets a disconnect message and never reaches the authenticator.
    var asked = new List<string>();
    var blocked = await Attempt((server, _) => { asked.Add(server.Name); return Task.FromResult(false); }, null);
    await blocked.Handling;
    Check(asked.SequenceEqual(new[] { "Hypixel" }), "Player was not asked before joining.");
    Check(blocked.Reply.Length > 0 && blocked.Reply[0] == 0, "Blocked join did not get a disconnect message.");
    Check(blocked.Auth.Calls == 0 && events.Contains("broker:blocked:127.0.0.1"), "Blocked join reached authentication.");

    // While a connection holds the shared slot, any other connection (any server) is refused before approval or login.
    var slot = new BrokerGate(); Check(slot.TryEnter(), "Gate not free.");
    bool approvalAsked = false;
    var busy = await Attempt((_, _) => { approvalAsked = true; return Task.FromResult(true); }, slot);
    await Throws<InvalidOperationException>(() => busy.Handling);
    Check(!approvalAsked && busy.Auth.Calls == 0 && events.Contains("broker:busy:127.0.0.1"), "Second connection was not refused.");
}

// A minimal online-mode server: encryption, login success, then sends `fill` bytes forever (or until closed).
static (int Port, Task Done) MockOnlineServer(TcpListener listener, CancellationToken ct)
{
    int port = ((IPEndPoint)listener.LocalEndpoint).Port;
    var done = Task.Run(async () =>
    {
        using var rsa = RSA.Create(1024); byte[] pub = rsa.ExportSubjectPublicKeyInfo();
        using var c = await listener.AcceptTcpClientAsync(ct); Stream raw = c.GetStream();
        await PacketIO.ReadAsync(raw, -1, ct); await PacketIO.ReadAsync(raw, -1, ct);
        await PacketIO.WriteAsync(raw, PacketIO.Packet(1, s => { PacketIO.WriteString(s, ""); PacketIO.WriteBytes(s, pub); PacketIO.WriteBytes(s, [1, 2, 3, 4]); s.WriteByte(1); }), -1, ct);
        var response = await PacketIO.ReadAsync(raw, -1, ct); int o = 0; PacketIO.ReadVarInt(response, ref o);
        byte[] secret = rsa.Decrypt(PacketIO.ReadBytes(response, ref o, 4096), RSAEncryptionPadding.Pkcs1);
        using var encrypted = new CipherStream(raw, secret);
        await PacketIO.WriteAsync(encrypted, PacketIO.Packet(2, s => { s.Write(Convert.FromHexString(Profile().Id)); PacketIO.WriteString(s, Profile().Name); PacketIO.WriteVarInt(s, 0); }), -1, ct);
        await PacketIO.ReadAsync(encrypted, -1, ct);
        try { while (!ct.IsCancellationRequested) { await PacketIO.WriteAsync(encrypted, [0x20, 1], -1, ct); await Task.Delay(5, ct); } }
        catch (Exception) { }
    }, ct);
    return (port, done);
}

static async Task<TcpClient> Join(int brokerPort, CancellationToken ct)
{
    var game = new TcpClient(); await game.ConnectAsync(IPAddress.Loopback, brokerPort, ct);
    try
    {
        await PacketIO.WriteAsync(game.GetStream(), PacketIO.Handshake("ignored", 1, 2), -1, ct);
        await PacketIO.WriteAsync(game.GetStream(), PacketIO.LoginStart(Profile()), -1, ct);
    }
    catch (Exception ex) when (ex is IOException or InvalidOperationException) { } // a refused connection may already be closed
    return game;
}

static async Task<string> DisconnectText(Stream stream, CancellationToken ct)
{
    byte[] packet = await PacketIO.ReadAsync(stream, -1, ct); int o = 0;
    Check(PacketIO.ReadVarInt(packet, ref o) == 0, "Expected a disconnect.");
    return PacketIO.ReadString(packet, ref o);
}

static async Task BrokerHardeningTests()
{
    using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20)); var ct = timeout.Token;

    // 1. Connections that don't come from the game are refused before anything happens.
    var events = new List<string>();
    var origin = new ConnectionOrigin();
    var auth = new MockAuthenticator(new TaskCompletionSource<string>());
    var listener = ConnectionBroker.Listen(); int port = ((IPEndPoint)listener.LocalEndpoint).Port;
    using var stop = CancellationTokenSource.CreateLinkedTokenSource(ct);
    Task running = new ConnectionBroker(new ServerEntry("x", "127.0.0.1", 9), Profile(), auth, e => { lock (events) events.Add(e); }, null, null, 775, origin).RunAsync(listener, stop.Token);
    using (var foreign = await Join(port, ct))
    {
        int read = 0;
        try { read = await foreign.GetStream().ReadAsync(new byte[16], ct); } catch (Exception ex) when (ex is IOException or InvalidOperationException) { }
        Check(read == 0 && auth.Calls == 0, "A connection from outside the game was served.");
    }
    lock (events) Check(events.Contains("broker:foreign:127.0.0.1"), "Foreign connection not reported.");
    // Once the check recognises the caller (in the app: a process in the game's job), it is served.
    IPEndPoint? seen = null;
    origin.Allow((client, server) => { seen = client; return server.Port == port; });
    using (var game = await Join(port, ct))
    {
        string reason = await DisconnectText(game.GetStream(), ct); // port 9 is closed: a normal failure, after the check passed
        Check(seen is not null && reason.Contains("connect to 127.0.0.1", StringComparison.Ordinal), "Recognised game connection not served: " + reason);
    }
    stop.Cancel(); await running;

    // 2. After the session's sign-in expires, no new sign-in happens and the game is told why.
    var local = new TcpListener(IPAddress.Loopback, 0); local.Start();
    var expiredAuth = new MockAuthenticator(new TaskCompletionSource<string>());
    var expired = new ConnectionBroker(new ServerEntry("x", "127.0.0.1", 9), Profile(), expiredAuth, _ => { }, null, null, 775, null, DateTimeOffset.UtcNow.AddMinutes(-1));
    using (var game = new TcpClient())
    {
        await game.ConnectAsync(IPAddress.Loopback, ((IPEndPoint)local.LocalEndpoint).Port, ct);
        using var accepted = await local.AcceptTcpClientAsync(ct);
        Task handling = expired.HandleAsync(accepted.GetStream(), ct);
        await PacketIO.WriteAsync(game.GetStream(), PacketIO.Handshake("x", 1, 2), -1, ct);
        await PacketIO.WriteAsync(game.GetStream(), PacketIO.LoginStart(Profile()), -1, ct);
        Check((await DisconnectText(game.GetStream(), ct)).Contains("expired", StringComparison.Ordinal) && expiredAuth.Calls == 0, "Expired session signed in.");
        await handling;
    }

    // 3. The reconnect limit is shared by every server's broker.
    var gate = new BrokerGate();
    async Task<string> Attempt(ConnectionBroker broker)
    {
        using var game = new TcpClient(); await game.ConnectAsync(IPAddress.Loopback, ((IPEndPoint)local.LocalEndpoint).Port, ct);
        using var accepted = await local.AcceptTcpClientAsync(ct);
        Task handling = broker.HandleAsync(accepted.GetStream(), ct);
        await PacketIO.WriteAsync(game.GetStream(), PacketIO.Handshake("x", 1, 2), -1, ct);
        await PacketIO.WriteAsync(game.GetStream(), PacketIO.LoginStart(Profile()), -1, ct);
        string text = await DisconnectText(game.GetStream(), ct);
        try { await handling; } catch (Exception) { }
        return text;
    }
    await Attempt(new ConnectionBroker(new ServerEntry("a", "127.0.0.1", 9), Profile(), new MockAuthenticator(new()), _ => { }, null, gate));
    Check((await Attempt(new ConnectionBroker(new ServerEntry("b", "127.0.0.1", 9), Profile(), new MockAuthenticator(new()), _ => { }, null, gate)))
        .Contains("too quickly", StringComparison.Ordinal), "Reconnect limit is per server, not shared.");

    // 4. A live connection keeps running until the player presses Disconnect.
    var remote = new TcpListener(IPAddress.Loopback, 0); remote.Start();
    using var serverStop = CancellationTokenSource.CreateLinkedTokenSource(ct);
    var (remotePort, serverDone) = MockOnlineServer(remote, serverStop.Token);
    var liveGate = new BrokerGate();
    var liveEvents = new List<string>();
    var live = new ConnectionBroker(new ServerEntry("x", "127.0.0.1", remotePort), Profile(), new MockAuthenticator(new()), e => { lock (liveEvents) liveEvents.Add(e); }, null, liveGate);
    using (var game = new TcpClient())
    {
        await game.ConnectAsync(IPAddress.Loopback, ((IPEndPoint)local.LocalEndpoint).Port, ct);
        using var accepted = await local.AcceptTcpClientAsync(ct);
        Task handling = live.HandleAsync(accepted.GetStream(), ct);
        var gs = game.GetStream();
        await PacketIO.WriteAsync(gs, PacketIO.Handshake("x", 1, 2), -1, ct);
        await PacketIO.WriteAsync(gs, PacketIO.LoginStart(Profile()), -1, ct);
        Check((await PacketIO.ReadAsync(gs, -1, ct))[0] == 2, "Login success missing.");
        await PacketIO.WriteAsync(gs, [3], -1, ct);
        await PacketIO.ReadAsync(gs, -1, ct);
        lock (liveEvents) Check(liveEvents.Contains("broker:connected:127.0.0.1"), "Live connection not reported.");
        Check(liveGate.DisconnectActive(), "Disconnect found no live connection.");
        await handling.WaitAsync(TimeSpan.FromSeconds(5), ct);
        lock (liveEvents) Check(liveEvents.Contains("broker:disconnected:127.0.0.1"), "Disconnect not reported.");
        Check(!liveGate.DisconnectActive(), "Connection still marked live.");
    }
    serverStop.Cancel(); try { await serverDone; } catch (Exception) { }
    remote.Stop(); local.Stop();
}

static async Task ApiHardeningTests()
{
    var config = new Configuration { HttpsPort = Port(), AllowChatSigning = false };
    using var identity = new MinecraftIdentity(new SecretValue("real-access-canary"), Profile(), DateTimeOffset.UtcNow.AddHours(1));
    string fake = FakeToken.Create(Profile(), identity.ExpiresAt);
    using var cert = LocalCertificate.Create();
    var handler = new MockApi(); using var upstream = new HttpClient(handler);
    await using var app = new HttpsVault(config, identity, fake, cert, upstream, _ => { }).Create();
    await app.StartAsync();
    using var localHandler = new HttpClientHandler { UseProxy = false, ServerCertificateCustomValidationCallback = (_, peer, _, _) => peer?.GetCertHashString() == cert.GetCertHashString() };
    using var client = new HttpClient(localHandler) { BaseAddress = new Uri($"https://127.0.0.1:{config.HttpsPort}") };
    try
    {
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", fake);
        using (var certificates = await client.PostAsync("/services/player/certificates", null))
            Check(certificates.StatusCode == HttpStatusCode.Forbidden && handler.Calls == 0, "Chat-signing key served while signed chat is off.");
        using (var attributes = await client.GetAsync("/services/player/attributes"))
            Check(attributes.IsSuccessStatusCode, "Allowed call refused.");
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "guess");
        var codes = new List<HttpStatusCode>();
        for (int i = 0; i < 125; i++) { using var r = await client.GetAsync("/services/player/attributes"); codes.Add(r.StatusCode); }
        Check(codes.Contains(HttpStatusCode.TooManyRequests), "Wrong-token guesses are not rate-limited.");
    }
    finally { await app.StopAsync(); }
}

static Task Cfb8BatchTests()
{
    // Reference: CFB8 straight from its definition, one AES block per byte.
    static byte[] Reference(byte[] key, byte[] input, bool encrypt)
    {
        using var aes = Aes.Create(); aes.Key = key;
        byte[] register = key.ToArray(), output = new byte[input.Length], block = new byte[16];
        for (int i = 0; i < input.Length; i++)
        {
            aes.EncryptEcb(register, block, PaddingMode.None);
            output[i] = (byte)(input[i] ^ block[0]);
            Buffer.BlockCopy(register, 1, register, 0, 15);
            register[15] = encrypt ? output[i] : input[i];
        }
        return output;
    }
    for (int round = 0; round < 20; round++)
    {
        byte[] key = RandomNumberGenerator.GetBytes(16), plain = RandomNumberGenerator.GetBytes(RandomNumberGenerator.GetInt32(1, 20000));
        byte[] cipher = Reference(key, plain, true);
        using var decryptor = MinecraftCrypto.CreateCipher(key, false);
        byte[] output = new byte[plain.Length];
        for (int done = 0; done < cipher.Length;)
        {
            int n = Math.Min(cipher.Length - done, RandomNumberGenerator.GetInt32(1, 9000));
            byte[] chunk = cipher[done..(done + n)];
            decryptor.TransformBlock(chunk, 0, n, chunk, 0); // in place, as CipherStream does
            chunk.CopyTo(output, done); done += n;
        }
        Check(output.SequenceEqual(plain), "Batched CFB8 decryption differs from the definition.");
        using var encryptor = MinecraftCrypto.CreateCipher(key, true);
        Check(encryptor.TransformFinalBlock(plain, 0, plain.Length).SequenceEqual(cipher), "CFB8 encryption differs from the definition.");
    }
    byte[] big = RandomNumberGenerator.GetBytes(16 * 1024 * 1024);
    using (var decrypt = MinecraftCrypto.CreateCipher(new byte[16], false))
    {
        var watch = System.Diagnostics.Stopwatch.StartNew();
        for (int at = 0; at < big.Length; at += 65536) decrypt.TransformBlock(big, at, 65536, big, at);
        Console.WriteLine($"     (CFB8 decryption: {big.Length / 1048576.0 / watch.Elapsed.TotalSeconds:0} MiB/s on one core)");
    }
    return Task.CompletedTask;
}

static async Task PackImportTests()
{
    string dir = Path.Combine(Path.GetTempPath(), "vault-import-test-" + Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(dir);
    var created = new List<Instance>();
    try
    {
        byte[] Jar(string entry, string text)
        {
            using var ms = new MemoryStream();
            using (var zip = new System.IO.Compression.ZipArchive(ms, System.IO.Compression.ZipArchiveMode.Create, true))
            using (var w = new StreamWriter(zip.CreateEntry(entry).Open())) w.Write(text);
            return ms.ToArray();
        }
        string pack = Path.Combine(dir, "my-dotminecraft.zip");
        using (var zip = System.IO.Compression.ZipFile.Open(pack, System.IO.Compression.ZipArchiveMode.Create))
        {
            void Add(string path, byte[] data) { using var s = zip.CreateEntry(path).Open(); s.Write(data); }
            byte[] canary = "SYNTHETIC-CANARY-NOT-A-TOKEN"u8.ToArray();
            Add(".minecraft/mods/a.jar", Jar("fabric.mod.json", "{\"id\":\"a\",\"depends\":{\"minecraft\":\"~1.20.1\"}}"));
            Add(".minecraft/mods/b.jar", Jar("fabric.mod.json", "{\"id\":\"b\",\"depends\":{\"minecraft\":\">=1.20.1 <1.21\"}}"));
            Add(".minecraft/config/sodium.json", "{}"u8.ToArray());
            Add(".minecraft/options.txt", "fov:1"u8.ToArray());
            foreach (string secret in new[] { "essential/microsoft_accounts.json", "TlauncherProfiles.json", "meteor-client/accounts.nbt",
                         "launcher_accounts.json", "feather/accounts.json", "config/someclient/alts.encrypted_json", "config/tokens.json", "versions/x/x.jar" })
                Add(".minecraft/" + secret, canary);
        }
        using var http = PackImporter.CreateHttp();
        var instance = await new PackImporter(http).ImportAsync(pack, null, default);
        created.Add(instance);
        var files = Directory.EnumerateFiles(instance.Directory, "*", SearchOption.AllDirectories).Select(f => Path.GetRelativePath(instance.Directory, f).Replace('\\', '/')).ToList();
        Check(files.Order().SequenceEqual(new[] { "config/sodium.json", "mods/a.jar", "mods/b.jar", "options.txt" }), "Unexpected files copied: " + string.Join(", ", files));
        Check(files.All(f => !File.ReadAllText(Path.Combine(instance.Directory, f)).Contains("CANARY")), "A credential file reached the instance.");
        Check(instance.MinecraftVersion == "1.20.1" && instance.Loader == "fabric", $"Loose mods detected as {instance.MinecraftVersion}/{instance.Loader}.");
        foreach (string name in new[] { "microsoft_accounts.json", "TlauncherProfiles.json", "accounts.nbt", "alts.encrypted_json", "launcher_accounts.json" })
            Check(SafeFiles.IsCredentialFile("x/" + name), "Not treated as a credential file: " + name);
        Check(!SafeFiles.IsCredentialFile("config/sodium-options.json"), "Ordinary config treated as credential.");
    }
    finally
    {
        foreach (var i in created) try { Directory.Delete(i.Directory, true); } catch (IOException) { }
        Directory.Delete(dir, true);
    }
}

static async Task UpdaterTests()
{
    using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    string publicKey = Convert.ToBase64String(key.ExportSubjectPublicKeyInfo());
    byte[] package;
    using (var ms = new MemoryStream())
    {
        using (var zip = new System.IO.Compression.ZipArchive(ms, System.IO.Compression.ZipArchiveMode.Create, true))
        {
            using (var w = zip.CreateEntry("TokenVault/TokenVault.exe").Open()) w.Write("NEW-BUILD"u8);
            using (var w = zip.CreateEntry("TokenVault/AuthlibProbe.java").Open()) w.Write("class AuthlibProbe {}"u8);
        }
        package = ms.ToArray();
    }
    byte[] Manifest(string version, byte[] file) => Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new
    { product = "TokenVault", version, file = Updater.PackageName, sha256 = Convert.ToHexString(SHA256.HashData(file)).ToLowerInvariant(), size = file.Length }));
    string Sign(byte[] data, ECDsa signer) => Convert.ToBase64String(signer.SignData(data, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence));

    byte[] manifest = Manifest("1.2.0", package);
    Check(Updater.VerifyManifest(manifest, Sign(manifest, key), publicKey).Version == new Version(1, 2, 0), "Valid manifest refused.");
    byte[] altered = manifest.ToArray(); altered[^3] ^= 1;
    await Throws<UpdateException>(() => Task.Run(() => Updater.VerifyManifest(altered, Sign(manifest, key), publicKey)));
    using var other = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    await Throws<UpdateException>(() => Task.Run(() => Updater.VerifyManifest(manifest, Sign(manifest, other), publicKey)));
    Check(Updater.ParseTag("v1.2.3") == new Version(1, 2, 3) && Updater.ParseTag("v1.2") is null && Updater.ParseTag("1.2.3-beta") is null, "Tag parsing wrong.");

    // A mock of GitHub: the release API and the three release files.
    var files = new Dictionary<string, byte[]>();
    string release = "v1.2.0";
    var github = new MockGitHub(() => Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new
    {
        tag_name = release, html_url = "https://github.com/o/r/releases/tag/" + release, draft = false, prerelease = false,
        assets = new[] { Updater.PackageName, Updater.ManifestName, Updater.SignatureName }
            .Select(n => new { name = n, browser_download_url = "https://github.com/o/r/releases/download/" + release + "/" + n })
    })), files);
    using var http = new HttpClient(github);
    void Publish(byte[] zip, byte[] man, string sig) { files[Updater.PackageName] = zip; files[Updater.ManifestName] = man; files[Updater.SignatureName] = Encoding.ASCII.GetBytes(sig); }
    string staging = Path.Combine(Path.GetTempPath(), "vault-update-test-" + Guid.NewGuid().ToString("N"));
    try
    {
        Publish(package, manifest, Sign(manifest, key));
        Check(await new Updater(http, "o/r", publicKey, new Version(1, 2, 0)).CheckAsync(default) is null, "Same version offered as an update.");
        var updater = new Updater(http, "o/r", publicKey, new Version(1, 0, 0));
        var info = await updater.CheckAsync(default) ?? throw new Exception("Newer release not found.");
        Check(info.Installable && info.Version == new Version(1, 2, 0), "Release assets not found.");
        var staged = await updater.DownloadAsync(info, staging, default);
        Check(File.ReadAllText(staged.Executable) == "NEW-BUILD" && staged.Probe is not null, "Staged update wrong.");

        // In-place install: the running file is renamed, the new one takes its name.
        string app = Path.Combine(staging, "app"); Directory.CreateDirectory(app);
        string exe = Path.Combine(app, "TokenVault.exe"); File.WriteAllText(exe, "OLD-BUILD");
        Updater.Install(staged, exe);
        Check(File.ReadAllText(exe) == "NEW-BUILD" && File.Exists(exe + ".old") && File.Exists(Path.Combine(app, "AuthlibProbe.java")), "Install did not swap the program.");
        Updater.CleanUp(exe);
        Check(!File.Exists(exe + ".old"), "Old program not cleaned up.");

        // A swapped package, a manifest signed by someone else, and a replayed older release are all refused.
        byte[] evil = package.ToArray(); evil[^10] ^= 1;
        Publish(evil, manifest, Sign(manifest, key));
        await Throws<UpdateException>(() => updater.DownloadAsync(info, staging, default));
        byte[] evilManifest = Manifest("1.2.0", evil);
        Publish(evil, evilManifest, Sign(evilManifest, other));
        await Throws<UpdateException>(() => updater.DownloadAsync(info, staging, default));
        byte[] old = Manifest("1.0.0", package);
        Publish(package, old, Sign(old, key));
        await Throws<UpdateException>(() => updater.DownloadAsync(info, staging, default));
        // Without a built-in key nothing is installed, only offered.
        Check(!new Updater(http, "o/r", "", new Version(1, 0, 0)).CanInstall, "Keyless build can install.");
        await Throws<UpdateException>(() => new Updater(http, "o/r", "", new Version(1, 0, 0)).DownloadAsync(info, staging, default));
        // Downloads may only come from GitHub.
        github.Redirect = "https://evil.invalid/x";
        await Throws<UpdateException>(() => updater.DownloadAsync(info, staging, default));
    }
    finally { if (Directory.Exists(staging)) Directory.Delete(staging, true); }
}

static Task TelemetryTests()
{
    string id = Guid.NewGuid().ToString("N");
    byte[] payload = Telemetry.Payload("game_launched", new Dictionary<string, string> { ["minecraft_version"] = "1.21.1", ["loader"] = "fabric" },
        "phc_test", id, "1.1.0", "10.0.22631", DateTimeOffset.UnixEpoch);
    using var json = JsonDocument.Parse(payload);
    var props = json.RootElement.GetProperty("properties");
    Check(json.RootElement.GetProperty("distinct_id").GetString() == id && json.RootElement.GetProperty("event").GetString() == "game_launched", "Payload shape wrong.");
    Check(props.GetProperty("$geoip_disable").GetBoolean() && !props.GetProperty("$process_person_profile").GetBoolean(), "Location/person profile not disabled.");
    var keys = props.EnumerateObject().Select(p => p.Name).Order().ToArray();
    Check(keys.SequenceEqual(new[] { "$geoip_disable", "$lib", "$lib_version", "$process_person_profile", "app_version", "loader", "minecraft_version", "os_version" }), "Unexpected properties: " + string.Join(",", keys));
    foreach (var (name, props2) in new (string, Dictionary<string, string>?)[]
    {
        ("anything_else", null), ("game_launched", new() { ["username"] = "VaultTester" }), ("game_launched", new() { ["loader"] = "a@b.c" }),
        ("join_approved", new() { ["source"] = "play.example.net:25565" })
    })
        try { Telemetry.Payload(name, props2, "phc_test", id, "1", "1", DateTimeOffset.UnixEpoch); throw new Exception("Statistics accepted: " + name); }
        catch (ArgumentException) { }
    Check(!new Telemetry(new HttpClient(), () => true, id, "phx_personal_key", "https://us.i.posthog.com").Configured, "A personal API key was accepted.");
    Check(!new Telemetry(new HttpClient(), () => true, id, "phc_x", "http://us.i.posthog.com").Configured, "Plain HTTP endpoint accepted.");
    Check(new Telemetry(new HttpClient(), () => true, id, "phc_x", "https://us.i.posthog.com").Configured, "Valid configuration refused.");
    return Task.CompletedTask;
}

static async Task ProbeFixture(string directory)
{
    Directory.CreateDirectory(directory);
    var config = new Configuration { HttpsPort = Port() };
    using var identity = new MinecraftIdentity(new SecretValue("synthetic-test-canary"), Profile(), DateTimeOffset.UtcNow.AddHours(1));
    using var cert = LocalCertificate.Create(); using var upstream = new HttpClient(new MockApi());
    string fake = FakeToken.Create(Profile(), identity.ExpiresAt);
    await File.WriteAllBytesAsync(Path.Combine(directory, "certificate.cer"), cert.Export(System.Security.Cryptography.X509Certificates.X509ContentType.Cert));
    await using var app = new HttpsVault(config, identity, fake, cert, upstream, _ => { }).Create();
    await app.StartAsync();
    // Synthetic fixture credentials only, to the test coordinator's anonymous pipe; never a log file.
    Console.WriteLine(JsonSerializer.Serialize(new { config.HttpsPort, Fake = fake }));
    while (!File.Exists(Path.Combine(directory, "stop"))) await Task.Delay(100);
    await app.StopAsync();
}

static async Task ModrinthTests()
{
    byte[] jar = "not really a jar, but hashed like one"u8.ToArray();
    string sha512 = Convert.ToHexString(SHA512.HashData(jar)).ToLowerInvariant();
    string File(string name, string url = "https://cdn.modrinth.com/data/x/", string? hash = null) =>
        $"{{\"filename\":\"{name}\",\"url\":\"{url}{name}\",\"primary\":true,\"size\":{jar.Length},\"hashes\":{{\"sha512\":\"{hash ?? sha512}\"}}}}";
    string Version(string type, string file, string dependencies = "") =>
        $"{{\"version_type\":\"{type}\",\"game_versions\":[\"1.21.1\"],\"loaders\":[\"fabric\"],\"files\":[{file}],\"dependencies\":[{dependencies}]}}";
    var api = new MockModrinth(jar)
    {
        ["search"] = """{"hits":[{"project_id":"AAAA1111","slug":"sodium","title":"Sodium","description":"fast\u0007 and\n small","author":"x","downloads":5,"icon_url":"https://evil.example/i.png"},{"project_id":"../x","title":"bad"}]}""",
        ["project/AAAA1111/version"] = $"[{Version("beta", File("sodium-beta.jar"))},{Version("release", File("sodium.jar"),
            """{"project_id":"BBBB2222","dependency_type":"required"},{"project_id":"CCCC3333","dependency_type":"optional"}""")}]",
        ["project/BBBB2222/version"] = $"[{Version("release", File("fabric-api.jar"))}]",
        ["project/AAAA1111"] = """{"title":"Sodium","slug":"sodium"}""",
        ["project/BBBB2222"] = """{"title":"Fabric API","slug":"fabric-api"}""",
        ["project/DDDD4444/version"] = $"[{Version("release", File("evil.jar", "https://evil.example/"))}]",
        ["project/EEEE5555/version"] = $"[{Version("release", File("short.jar", hash: "abc"))}]",
        ["project/FFFF6666/version"] = $"[{Version("release", File("notes.txt"))}]",
    };
    using var http = new HttpClient(api);
    var client = new ModrinthClient(http);
    var none = new HashSet<string>();

    var hits = await client.SearchAsync("sodium", "1.21.1", "fabric", default);
    Check(hits.Count == 1 && hits[0].ProjectId == "AAAA1111" && hits[0].Slug == "sodium", "Search results not parsed, or an unsafe project id was kept.");
    Check(hits[0].Icon is null, "Icon from outside Modrinth's CDN was kept.");
    Check(hits[0].Description == "fast and small", "Control characters or line breaks reached the window.");
    Check(api.Requests.Any(r => r.Contains("versions%3A1.21.1") && r.Contains("categories%3Afabric")), "Search wasn't narrowed to the instance's version and loader.");
    Check((await client.SearchAsync("x", "1.21.1", "vanilla", default)).Count == 0, "Vanilla instances searched for mods.");

    var files = await client.ResolveAsync("AAAA1111", "1.21.1", "fabric", none, none, default);
    Check(files.Select(f => f.FileName).SequenceEqual(["sodium.jar", "fabric-api.jar"]), "Expected the release (not the newer beta) plus its required dependency only.");
    files = await client.ResolveAsync("AAAA1111", "1.21.1", "fabric", none, new HashSet<string>(["fabric-api"]), default);
    Check(files.Count == 1, "A dependency already in the mods folder (by mod id) was downloaded again.");
    files = await client.ResolveAsync("AAAA1111", "1.21.1", "fabric", new HashSet<string>(["BBBB2222"]), none, default);
    Check(files.Count == 1, "A dependency already installed from Modrinth was downloaded again.");
    foreach (string bad in new[] { "DDDD4444", "EEEE5555", "FFFF6666" })
        try { await client.ResolveAsync(bad, "1.21.1", "fabric", none, none, default); throw new Exception("Accepted a file that isn't a checksummed .jar from Modrinth's CDN: " + bad); }
        catch (UserVisibleException) { }

    var instance = new Instance { Name = "modrinth-test", MinecraftVersion = "1.21.1" };
    InstanceStore.CreateFolder(instance);
    try
    {
        var importer = new PackImporter(http);
        var sodium = (await client.ResolveAsync("AAAA1111", "1.21.1", "fabric", none, none, default))[0];
        await importer.InstallModAsync(instance, sodium, default);
        Check(System.IO.File.ReadAllBytes(Path.Combine(instance.ModsDirectory, "sodium.jar")).SequenceEqual(jar), "Installed mod differs from the download.");
        Check(instance.ModrinthProjects().SetEquals(["AAAA1111"]), "Installed mod wasn't recorded as coming from Modrinth.");
        try { await importer.InstallModAsync(instance, sodium with { FileName = "tampered.jar", Sha512 = new string('0', 128) }, default); throw new Exception("A download with the wrong checksum was installed."); }
        catch (UserVisibleException) { }
        Check(!System.IO.File.Exists(Path.Combine(instance.ModsDirectory, "tampered.jar")), "A file that failed its checksum was left in the mods folder.");
        try { await importer.InstallModAsync(instance, sodium with { Url = new Uri("https://evil.example/sodium.jar") }, default); throw new Exception("Installed from outside Modrinth's CDN."); }
        catch (UserVisibleException) { }
    }
    finally { InstanceStore.DeleteFolder(instance); }
}
sealed class MockApi : HttpMessageHandler
{
    public int Calls;
    public string? Authorization;
    public string Body = "{\"privileges\":{\"multiplayerServer\":{\"enabled\":true}},\"banStatus\":{\"bannedScopes\":{}}}";
    public HttpStatusCode Status = HttpStatusCode.OK;
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        Calls++; Authorization = request.Headers.Authorization?.ToString();
        return Task.FromResult(new HttpResponseMessage(Status) { Content = new StringContent(Body) });
    }
}

sealed class MockAuthenticator(TaskCompletionSource<string> completion) : IConnectionAuthenticator
{
    public int Calls;
    public Task AuthorizeOwnedConnectionAsync(string serverHash, CancellationToken ct)
    { Calls++; completion.TrySetResult(serverHash); return Task.CompletedTask; }
}

sealed class XorWrap(byte id) : IKeyWrap
{
    private static readonly byte[] Pad = RandomNumberGenerator.GetBytes(32);
    public byte Id => id;
    public byte[] Wrap(byte[] key) => key.Select((b, i) => (byte)(b ^ Pad[i % 32])).ToArray();
    public byte[] Unwrap(byte[] wrapped) => Wrap(wrapped);
}

sealed class MockGitHub(Func<byte[]> release, Dictionary<string, byte[]> files) : HttpMessageHandler
{
    public string? Redirect;
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var url = request.RequestUri!;
        if (url.Host == "api.github.com") return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(release()) });
        if (url.Host == "github.com")
        {
            var response = new HttpResponseMessage(HttpStatusCode.Found);
            response.Headers.Location = new Uri(Redirect ?? "https://release-assets.githubusercontent.com/" + url.Segments[^1]);
            return Task.FromResult(response);
        }
        if (url.Host.EndsWith(".githubusercontent.com") && files.TryGetValue(url.Segments[^1], out var data))
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(data) });
        return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
    }
}

// Answers Modrinth API paths from a table (query strings ignored) and serves one file from cdn.modrinth.com.
sealed class MockModrinth(byte[] file) : HttpMessageHandler
{
    private readonly Dictionary<string, string> routes = [];
    public List<string> Requests { get; } = [];
    public string this[string path] { set => routes[path] = value; }
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var url = request.RequestUri!;
        Requests.Add(url.AbsoluteUri);
        if (url.Host == "cdn.modrinth.com") return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(file) });
        if (url.Host == "api.modrinth.com" && routes.TryGetValue(url.AbsolutePath["/v2/".Length..], out var json))
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(json) });
        return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
    }
}