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
    ("OAuth loopback rejects wrong state and requires PKCE", OAuthCallbackTests),
    ("API deny ceiling, TLS, token substitution and response non-disclosure", HttpTests),
    ("owned online login, Fabric query, compression and encrypted relay", BrokerTests),
    ("offline upstream refusal before gameplay", OfflineTests),
    ("sandbox folder policy, command-line quoting and Java truststore format", SandboxTests),
    ("server list file, server addresses, pack detection and pack path safety", PackTests),
    ("join approval and one connection at a time", ApprovalTests)
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
        using var remote = await listener.AcceptTcpClientAsync(ct); Stream raw = remote.GetStream();
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
    }, ct);
    var local = new TcpListener(IPAddress.Loopback, 0); local.Start();
    using var game = new TcpClient(); await game.ConnectAsync(IPAddress.Loopback, ((IPEndPoint)local.LocalEndpoint).Port, ct);
    using var brokerSocket = await local.AcceptTcpClientAsync(ct);
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
        game.Close(); await server; await relay;
    }
    finally { listener.Stop(); local.Stop(); deadline.Cancel(); }
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

        // Only Minecraft 26.1.2 + Fabric packs are accepted, before anything is downloaded.
        PackImporter.RequireCompatible("26.1.2", "0.19.5", null);
        PackImporter.RequireCompatible(null, null, null);
        try { PackImporter.RequireCompatible("1.21.1", "0.16.0", null); throw new Exception("Wrong version accepted."); } catch (UserVisibleException) { }
        try { PackImporter.RequireCompatible("26.1.2", null, "Forge"); throw new Exception("Forge accepted."); } catch (UserVisibleException) { }
    }
    finally { Directory.Delete(dir, true); }
    return Task.CompletedTask;
}

static async Task ApprovalTests()
{
    using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10)); var ct = timeout.Token;
    var events = new List<string>();
    async Task<(byte[] Reply, Task Handling, MockAuthenticator Auth)> Attempt(JoinApproval? approve, SemaphoreSlim? slot)
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
    var slot = new SemaphoreSlim(0, 1);
    bool approvalAsked = false;
    var busy = await Attempt((_, _) => { approvalAsked = true; return Task.FromResult(true); }, slot);
    await Throws<InvalidOperationException>(() => busy.Handling);
    Check(!approvalAsked && busy.Auth.Calls == 0 && events.Contains("broker:busy:127.0.0.1"), "Second connection was not refused.");
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
