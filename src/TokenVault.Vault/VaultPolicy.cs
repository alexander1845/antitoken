namespace TokenVault.Vault;

public static class VaultPolicy
{
    private static readonly HashSet<string> Ceiling =
    ["GET /services/player/attributes", "POST /services/player/certificates", "GET /services/publickeys"];

    public static bool IsAllowed(string[] configured, string method, string path)
    {
        string key = method + " " + path;
        // Configuration can narrow this set, NEVER enable /join or arbitrary authenticated actions.
        return Ceiling.Contains(key) && configured.Contains(key, StringComparer.Ordinal);
    }
    public static bool IsPublic(string method, string path) => method == "GET" && path == "/services/publickeys";
    public static string Upstream(string path) => path switch
    {
        "/services/player/attributes" => "https://api.minecraftservices.com/player/attributes",
        "/services/player/certificates" => "https://api.minecraftservices.com/player/certificates",
        "/services/publickeys" => "https://api.minecraftservices.com/publickeys",
        _ => throw new InvalidOperationException("No upstream mapping.")
    };
    public static string Classify(string method, string path)
    {
        if (path.EndsWith("/session/minecraft/join", StringComparison.Ordinal)) return "join-always-denied";
        return Ceiling.Contains(method + " " + path) ? path : "denied:" + SanitizePath(path);
    }
    public static string SanitizePath(string path) => string.Join('/', path.Split('/').Take(8).Select(s =>
        s.Length <= 32 && s.All(ch => char.IsAsciiLetter(ch) || ch is '-' or '_') ? s : "[redacted]"));
}
