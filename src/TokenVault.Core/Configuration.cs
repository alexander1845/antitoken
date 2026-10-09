using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace TokenVault.Core;

public sealed class Configuration
{
    public string ClientId { get; set; } = "REPLACE_WITH_YOUR_APPROVED_APPLICATION_ID";
    public int OAuthPort { get; set; } = 25597;
    public int HttpsPort { get; set; } = 25599;
    public int GamePort { get; set; } = 25598;
    public string ServerHost { get; set; } = "";
    public int ServerPort { get; set; } = 25565;
    public string MinecraftVersion { get; set; } = "26.1.2";
    public string FabricProfile { get; set; } = "fabric-loader-0.19.5-26.1.2";
    // Official launcher install (versions/, libraries/, assets/). The sandbox only ever gets READ access to
    // those three subfolders, never to the root, which also holds the official launcher's sign-in files.
    public string MinecraftDirectory { get; set; } = "%APPDATA%/.minecraft";
    // Sandbox-writable instance (saves, options, logs, configs). Must not be .minecraft itself.
    public string GameDirectory { get; set; } = "%LOCALAPPDATA%/TokenVault/Instance";
    public string ModsDirectory { get; set; } = "%LOCALAPPDATA%/TokenVault/Instance/mods";
    public string JavaPath { get; set; } = ""; // Empty: use the Java runtime the official launcher installed.
    public int MemoryMb { get; set; } = 4096;
    public int SessionMinutes { get; set; } = 240;
    public bool AllowClipboard { get; set; }
    public bool RememberSignIn { get; set; } = true;
    public bool ObserveDeniedEndpoints { get; set; }
    public string[] Allowlist { get; set; } =
        ["GET /services/player/attributes", "POST /services/player/certificates", "GET /services/publickeys"];

    private static readonly JsonSerializerOptions Json = new() { PropertyNameCaseInsensitive = true, WriteIndented = true };

    [JsonIgnore]
    public string FabricVersion =>
        Regex.Match(FabricProfile, @"^fabric-loader-(.+)-" + Regex.Escape(MinecraftVersion) + "$") is { Success: true } m
            ? m.Groups[1].Value : throw new InvalidDataException("Fabric profile must be named fabric-loader-<version>-" + MinecraftVersion + ".");

    public static Configuration Load(string path)
    {
        var c = JsonSerializer.Deserialize<Configuration>(File.ReadAllText(path), Json)
            ?? throw new InvalidDataException("Empty configuration.");
        c.Validate();
        return c;
    }

    public static Configuration LoadOrDefault(string path) => File.Exists(path) ? Load(path) : new Configuration();

    public void Save(string path)
    {
        Validate();
        string temp = path + ".new";
        File.WriteAllBytes(temp, JsonSerializer.SerializeToUtf8Bytes(this, Json));
        File.Move(temp, path, overwrite: true);
    }

    public void Validate()
    {
        if (MinecraftVersion != "26.1.2")
            throw new InvalidDataException("Only Minecraft 26.1.2 / protocol 775 is supported. Other versions fail closed.");
        if (new[] { HttpsPort, GamePort, OAuthPort }.Any(p => p is < 1024 or > 65535) ||
            new[] { HttpsPort, GamePort, OAuthPort }.Distinct().Count() != 3)
            throw new InvalidDataException("Use three distinct ports in 1024..65535.");
        if (ServerPort is < 1 or > 65535 || ServerHost.Length > 253 ||
            ServerHost.Any(ch => char.IsControl(ch) || char.IsWhiteSpace(ch) || ch is '/' or '\\' or '@'))
            throw new InvalidDataException("Invalid fixed target server.");
        if (SessionMinutes is < 1 or > 1440 || MemoryMb is < 512 or > 65536)
            throw new InvalidDataException("Invalid session duration or memory size.");
        _ = FabricVersion;
    }

    public static string Expand(string path) => Path.GetFullPath(Environment.ExpandEnvironmentVariables(path));
}

// Fixed per-user locations. Data is private to the Windows user and never granted to the game sandbox.
public static class AppPaths
{
    public static string Root => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "TokenVault");
    public static string Data => Path.Combine(Root, "Data");
    public static string Config => Path.Combine(Data, "config.json");
    public static string RefreshCache => Path.Combine(Data, "vault.bin");
    public static string AuditLog => Path.Combine(Data, "requests.log");
    // Per-launch folders (natives, truststore, temp). Created by the vault, then handed to the sandbox.
    public static string Run => Path.Combine(Root, "Run");
}

public sealed record PlayerProfile(string Id, string Name);

// Deliberately contains no real credential, upstream secret, or encryption key.
public sealed record SessionDescriptor(PlayerProfile Profile, string FakeToken, string CertificateDer,
    int HttpsPort, int GamePort, string MinecraftVersion, DateTimeOffset ExpiresAt);
