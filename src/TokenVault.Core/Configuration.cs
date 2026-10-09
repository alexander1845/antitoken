using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace TokenVault.Core;

public sealed class Configuration
{
    // Empty: use the built-in public sign-in app (see AuthenticationDefaults). Publishers set their own.
    public string ClientId { get; set; } = "";
    public bool UseDeviceCode { get; set; }
    public int OAuthPort { get; set; } = 25597;
    public int HttpsPort { get; set; } = 25599;
    // The only servers Token Vault will sign in to. Each gets its own local port per session.
    public List<ServerEntry> Servers { get; set; } = [];
    // Token Vault's own game install (versions/, libraries/, assets/, runtime/). Fixed, never the official launcher's
    // .minecraft (whose root holds that launcher's sign-in files), and not persisted, so old settings can't move it.
    [JsonIgnore] public string MinecraftDirectory { get; set; } = Path.Combine(AppPaths.GameRoot, "Minecraft");
    public string JavaPath { get; set; } = ""; // Empty: the Java runtime Token Vault installs
    public string SelectedInstance { get; set; } = "";
    public int MemoryMb { get; set; } = 4096;
    public int SessionMinutes { get; set; } = 240;
    public bool AllowClipboard { get; set; }
    // Ask in Token Vault's window before every server join, so a mod can't quietly join as you.
    public bool ConfirmJoins { get; set; } = true;
    public bool RememberSignIn { get; set; } = true;
    public bool ObserveDeniedEndpoints { get; set; }
    // Can only narrow Token Vault's built-in list of read-only requests (see VaultPolicy); never widen it.
    public string[] Allowlist { get; set; } =
        ["GET /services/player/attributes", "POST /services/player/certificates", "GET /services/publickeys",
         "GET /services/privileges", "GET /session/minecraft/profile"];

    // Per launch, filled from the selected instance; never persisted.
    [JsonIgnore] public string MinecraftVersion { get; set; } = DefaultVersion;
    [JsonIgnore] public string Loader { get; set; } = "fabric";            // vanilla | fabric | quilt | forge | neoforge
    [JsonIgnore] public string Profile { get; set; } = "fabric-loader-0.19.5-26.1.2"; // version id to launch
    [JsonIgnore] public string LoaderDirectory { get; set; } = "";       // Forge/NeoForge install folder, if any
    [JsonIgnore] public int Protocol { get; set; }                       // the client's network protocol, set at launch
    [JsonIgnore] public string GameDirectory { get; set; } = Path.Combine(AppPaths.InstanceRoot, "default");
    [JsonIgnore] public string ModsDirectory { get; set; } = Path.Combine(AppPaths.InstanceRoot, "default", "mods");

    public const string DefaultVersion = "26.1.2";

    private static readonly JsonSerializerOptions Json = new() { PropertyNameCaseInsensitive = true, WriteIndented = true };

    public static bool IsVersionId(string id) => Regex.IsMatch(id, @"^[0-9A-Za-z][0-9A-Za-z._+\- ]{0,63}$") && !id.Contains("..");

    public static Configuration Load(string path)
    {
        var c = JsonSerializer.Deserialize<Configuration>(File.ReadAllText(path), Json)
            ?? throw new InvalidDataException("Empty configuration.");
        c.Servers ??= [];
        c.Allowlist ??= [];
        // Settings saved by earlier builds list the original three requests; add the read-only ones introduced since.
        if (c.Allowlist.Order().SequenceEqual(new[] { "GET /services/player/attributes", "GET /services/publickeys", "POST /services/player/certificates" }))
            c.Allowlist = new Configuration().Allowlist;
        c.Validate();
        return c;
    }

    public static Configuration LoadOrDefault(string path) => File.Exists(path) ? Load(path) : new Configuration();

    public Configuration Clone() => JsonSerializer.Deserialize<Configuration>(JsonSerializer.SerializeToUtf8Bytes(this, Json), Json)!;

    public void Save(string path)
    {
        Validate();
        string temp = path + ".new";
        File.WriteAllBytes(temp, JsonSerializer.SerializeToUtf8Bytes(this, Json));
        File.Move(temp, path, overwrite: true);
    }

    public void Validate()
    {
        if (!IsVersionId(MinecraftVersion) || !IsVersionId(Profile)) throw new InvalidDataException("Invalid Minecraft version.");
        if (new[] { HttpsPort, OAuthPort }.Any(p => p is < 1024 or > 65535) || HttpsPort == OAuthPort)
            throw new InvalidDataException("Use two distinct ports in 1024..65535.");
        if (Servers.Count > 32) throw new InvalidDataException("Too many servers.");
        foreach (var server in Servers) server.Validate();
        if (SessionMinutes is < 1 or > 1440 || MemoryMb is < 512 or > 65536)
            throw new InvalidDataException("Invalid session duration or memory size.");
        if (ClientId.Length > 0 && !Guid.TryParse(ClientId, out _))
            throw new InvalidDataException("The Microsoft application ID must be a GUID, or empty to use the built-in one.");
    }

    public static string Expand(string path) => Path.GetFullPath(Environment.ExpandEnvironmentVariables(path));
}

public sealed record ServerEntry(string Name, string Host, int Port = 25565)
{
    public void Validate()
    {
        if (Port is < 1 or > 65535 || Host.Length is < 1 or > 253 || Name.Length > 64 ||
            Host.Any(ch => char.IsControl(ch) || char.IsWhiteSpace(ch) || ch is '/' or '\\' or '@' or ':') || Name.Any(char.IsControl))
            throw new InvalidDataException("Invalid server address.");
    }

    // Accepts "host" or "host:port" as typed by a player.
    public static ServerEntry Parse(string text, string? name = null)
    {
        text = text.Trim();
        string host = text;
        int port = 25565;
        int colon = text.IndexOf(':');
        if (colon >= 0)
        {
            host = text[..colon];
            if (!int.TryParse(text[(colon + 1)..], System.Globalization.NumberStyles.None, null, out port))
                throw new InvalidDataException("Use an address like play.example.net or play.example.net:25565.");
        }
        var entry = new ServerEntry(string.IsNullOrWhiteSpace(name) ? host : name.Trim(), host.ToLowerInvariant(), port);
        entry.Validate();
        return entry;
    }
}

// Fixed per-user locations. Data is private to the Windows user and never granted to the game sandbox.
public static class AppPaths
{
    public static string Root => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "TokenVault");
    public static string Data => Path.Combine(Root, "Data");
    public static string Config => Path.Combine(Data, "config.json");
    public static string Instances => Path.Combine(Data, "instances.json");
    public static string RefreshCache => Path.Combine(Data, "vault.bin");
    public static string AuditLog => Path.Combine(Data, "requests.log");
    // Everything the game touches lives under one folder at the top of the system drive. Java resolves real paths
    // by listing every parent folder, and a sandboxed process can't list folders inside the user profile, so the
    // game files can't live there. Locked to this Windows user (and SYSTEM/Administrators).
    // TOKENVAULT_GAME_ROOT can move it (e.g. to another drive); the one-time setup then covers that drive's root.
    public static string GameRoot => Environment.GetEnvironmentVariable("TOKENVAULT_GAME_ROOT") is { Length: > 0 } custom
        ? Path.GetFullPath(custom)
        : OperatingSystem.IsWindows()
        ? Path.Combine(Path.GetPathRoot(Environment.GetFolderPath(Environment.SpecialFolder.Windows)) ?? "C:" + Path.DirectorySeparatorChar, "TokenVault")
        : Path.Combine(Root, "Game");
    // Game folders (saves, mods, options) per instance. Created by the vault, then handed to the sandbox.
    public static string InstanceRoot => Path.Combine(GameRoot, "Instances");
    // Per-launch folders (natives, truststore, temp). Created by the vault, then handed to the sandbox.
    public static string Run => Path.Combine(GameRoot, "Run");
    // Where earlier builds kept instances, inside the user profile (migrated on start).
    public static string LegacyInstanceRoot => Path.Combine(Root, "Instances");
    // The official launcher's folder. Its root holds that launcher's sign-in files; never shared.
    public static string OfficialMinecraft => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), ".minecraft");
}

public sealed record PlayerProfile(string Id, string Name);

public sealed record LocalServer(string Name, int Port);

// Deliberately contains no real credential, upstream secret, or encryption key.
public sealed record SessionDescriptor(PlayerProfile Profile, string FakeToken, string CertificateDer,
    int HttpsPort, IReadOnlyList<LocalServer> Servers, string MinecraftVersion, DateTimeOffset ExpiresAt);
