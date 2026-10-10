using System.Text.RegularExpressions;
using TokenVault.Core;

namespace TokenVault.Vault;

public static class VaultPolicy
{
    // Every operation the game may ask for. All read-only; none can sign in anywhere or change the account.
    public const string ProfileLookup = "GET /session/minecraft/profile";
    private static readonly HashSet<string> Ceiling =
    [
        "GET /services/player/attributes", "POST /services/player/certificates", "GET /services/publickeys",
        "GET /services/privileges", // Minecraft 1.16.4-1.17
        ProfileLookup               // public skin/profile lookup, no token involved
    ];
    public static readonly string[] DefaultAllowlist = [.. Ceiling];

    // Authlib appends "/session/minecraft/profile/<uuid>" to the session host ".../session".
    private static readonly Regex ProfilePath = new("^/session/session/minecraft/profile/([0-9a-f]{32})$", RegexOptions.CultureInvariant);

    public static string Key(string method, string path) =>
        method == "GET" && ProfilePath.IsMatch(path) ? ProfileLookup : method + " " + path;

    public const string Certificates = "POST /services/player/certificates";

    // The configured list, minus the chat-signing key when the player turned signed chat off.
    public static string[] Effective(Configuration c) =>
        c.AllowChatSigning ? c.Allowlist : c.Allowlist.Where(k => k != Certificates).ToArray();

    public static bool IsAllowed(string[] configured, string method, string path)
    {
        string key = Key(method, path);
        // Configuration can narrow this set, NEVER enable /join or arbitrary authenticated actions.
        return Ceiling.Contains(key) && configured.Contains(key, StringComparer.Ordinal);
    }

    // Only the profile lookup accepts a query, and only Authlib's "unsigned" flag.
    public static bool IsAllowedQuery(string method, string path, string query) =>
        query.Length == 0 || (Key(method, path) == ProfileLookup && query is "?unsigned=false" or "?unsigned=true");

    public static bool IsPublic(string method, string path) => Key(method, path) is "GET /services/publickeys" or ProfileLookup;

    public static string Upstream(string path, string query = "") => path switch
    {
        "/services/player/attributes" => "https://api.minecraftservices.com/player/attributes",
        "/services/player/certificates" => "https://api.minecraftservices.com/player/certificates",
        "/services/publickeys" => "https://api.minecraftservices.com/publickeys",
        "/services/privileges" => "https://api.minecraftservices.com/privileges",
        _ when ProfilePath.Match(path) is { Success: true } m =>
            "https://sessionserver.mojang.com/session/minecraft/profile/" + m.Groups[1].Value + (query is "?unsigned=false" or "?unsigned=true" ? query : ""),
        _ => throw new InvalidOperationException("No upstream mapping.")
    };

    public static string Classify(string method, string path)
    {
        if (path.EndsWith("/session/minecraft/join", StringComparison.Ordinal)) return "join-always-denied";
        string key = Key(method, path);
        return Ceiling.Contains(key) ? key[(key.IndexOf(' ') + 1)..] : "denied:" + SanitizePath(path);
    }

    public static string SanitizePath(string path) => string.Join('/', path.Split('/').Take(8).Select(s =>
        s.Length <= 32 && s.All(ch => char.IsAsciiLetter(ch) || ch is '-' or '_') ? s : "[redacted]"));
}
