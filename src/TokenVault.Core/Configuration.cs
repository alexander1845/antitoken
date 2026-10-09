using System.Text.Json;

namespace TokenVault.Core;

public sealed class Configuration
{
    public string ClientId { get; set; } = "REPLACE_WITH_YOUR_APPROVED_APPLICATION_ID";
    public int OAuthPort { get; set; } = 25597;
    public int HttpsPort { get; set; } = 25599;
    public int GamePort { get; set; } = 25598;
    public string PipeName { get; set; } = "TokenVault.Session.v1";
    public string HardeningMode { get; set; } = "separate-user";
    public string GameUserSid { get; set; } = "";
    public string VaultUserSid { get; set; } = "";
    public string DataDirectory { get; set; } = "%LOCALAPPDATA%/TokenVault";
    public string ServerHost { get; set; } = "";
    public int ServerPort { get; set; } = 25565;
    public string MinecraftVersion { get; set; } = "26.1.2";
    public string FabricVersion { get; set; } = "0.19.5";
    public string FabricProfile { get; set; } = "fabric-loader-0.19.5-26.1.2";
    public string MinecraftDirectory { get; set; } = "%APPDATA%/.minecraft";
    public string GameDirectory { get; set; } = "%APPDATA%/.minecraft";
    public string ModsDirectory { get; set; } = "%APPDATA%/.minecraft/mods";
    public string JavaPath { get; set; } = "java.exe";
    public string KeytoolPath { get; set; } = "keytool.exe";
    public int MemoryMb { get; set; } = 4096;
    public int SessionMinutes { get; set; } = 120;
    public bool ObserveDeniedEndpoints { get; set; }
    public string[] Allowlist { get; set; } =
        ["GET /services/player/attributes", "POST /services/player/certificates", "GET /services/publickeys"];

    public static Configuration Load(string path)
    {
        var c = JsonSerializer.Deserialize<Configuration>(File.ReadAllText(path),
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true })
            ?? throw new InvalidDataException("Empty configuration.");
        c.Validate();
        return c;
    }

    public void Validate()
    {
        if (MinecraftVersion != "26.1.2")
            throw new InvalidDataException("Only Minecraft 26.1.2 / protocol 775 is supported. Other versions fail closed.");
        if (new[] { HttpsPort, GamePort, OAuthPort }.Any(p => p is < 1024 or > 65535) ||
            new[] { HttpsPort, GamePort, OAuthPort }.Distinct().Count() != 3)
            throw new InvalidDataException("Use three distinct ports in 1024..65535.");
        if (ServerPort is < 1 or > 65535 || ServerHost.Length > 253 ||
            ServerHost.Any(ch => char.IsControl(ch) || ch is '/' or '\\' or '@'))
            throw new InvalidDataException("Invalid fixed target server.");
        if (HardeningMode is not ("separate-user" or "same-user-development"))
            throw new InvalidDataException("Unknown hardening mode.");
        if (SessionMinutes is < 1 or > 1440 || MemoryMb is < 512 or > 65536)
            throw new InvalidDataException("Invalid session duration or memory size.");
        if (PipeName.Length is < 1 or > 100 || PipeName.Any(ch => !char.IsAsciiLetterOrDigit(ch) && ch is not ('.' or '-')))
            throw new InvalidDataException("Invalid pipe name.");
    }

    public static string Expand(string path) => Path.GetFullPath(Environment.ExpandEnvironmentVariables(path));
}

public sealed record PlayerProfile(string Id, string Name);

// Deliberately contains no real credential, upstream secret, or encryption key.
public sealed record SessionDescriptor(PlayerProfile Profile, string FakeToken, string CertificateDer,
    int HttpsPort, int GamePort, string MinecraftVersion, DateTimeOffset ExpiresAt);
