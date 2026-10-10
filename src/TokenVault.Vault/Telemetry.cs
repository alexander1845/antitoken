using System.Text.Json;
using System.Text.RegularExpressions;

namespace TokenVault.Vault;

// Anonymous usage statistics (PostHog), sent only after the player opts in and only when the build carries a PostHog
// project key. What can be sent is fixed here: one of the events below, the app and Windows version, and a few
// enumerated properties. Never the Minecraft account (name or id), Microsoft data, server addresses, file paths, mod
// names or anything that comes from the game. The identifier is a random per-install id, not tied to the account or PC.
// Location lookup from the IP address is disabled per event; also turn on "Discard client IP data" in the PostHog project.
public sealed class Telemetry(HttpClient http, Func<bool> enabled, string installId, string projectKey, string host)
{
    public static readonly IReadOnlySet<string> Events = new HashSet<string>(StringComparer.Ordinal)
    {
        "app_started", "consent_given", "game_launched", "game_exited", "join_approved", "join_blocked", "join_failed",
        "join_refused_foreign", "pack_imported", "update_available", "update_installed", "update_failed"
    };
    private static readonly IReadOnlySet<string> Properties = new HashSet<string>(StringComparer.Ordinal)
    {
        "minecraft_version", "loader", "result", "source", "from_version", "to_version", "protection",
        "confirm_joins", "chat_signing", "clipboard", "minutes"
    };

    public static Telemetry Create(Func<bool> enabled, string installId) =>
        new(new HttpClient { Timeout = TimeSpan.FromSeconds(10) }, enabled, installId, BuildInfo.PostHogProjectKey, BuildInfo.PostHogHost);

    public bool Configured => projectKey.StartsWith("phc_", StringComparison.Ordinal) && Endpoint(host) is not null;

    // Fire and forget: statistics never slow down or break anything.
    public void Track(string name, IReadOnlyDictionary<string, string>? properties = null)
    {
        if (!Configured || !enabled()) return;
        byte[] payload;
        try { payload = Payload(name, properties, projectKey, installId, BuildInfo.Version.ToString(), Environment.OSVersion.Version.ToString(), DateTimeOffset.UtcNow); }
        catch (ArgumentException) { return; }
        _ = Task.Run(async () =>
        {
            try
            {
                using var content = new ByteArrayContent(payload);
                content.Headers.ContentType = new("application/json");
                using var response = await http.PostAsync(Endpoint(host)!, content);
            }
            catch (Exception) { }
        });
    }

    public static Uri? Endpoint(string host) =>
        Uri.TryCreate(host, UriKind.Absolute, out var url) && url.Scheme == "https" && url.UserInfo.Length == 0 && url.AbsolutePath == "/"
            ? new Uri(url, "/capture/") : null;

    // The exact JSON sent. Refuses anything outside the fixed vocabulary, so a later change can't leak data by accident.
    public static byte[] Payload(string name, IReadOnlyDictionary<string, string>? properties, string projectKey, string installId,
        string appVersion, string osVersion, DateTimeOffset time)
    {
        if (!Events.Contains(name)) throw new ArgumentException("Unknown statistics event.");
        if (!Guid.TryParseExact(installId, "N", out _)) throw new ArgumentException("Invalid install id.");
        var fields = new Dictionary<string, object?>
        {
            ["app_version"] = appVersion, ["os_version"] = osVersion,
            ["$lib"] = "tokenvault", ["$lib_version"] = appVersion,
            ["$process_person_profile"] = false, ["$geoip_disable"] = true
        };
        foreach (var (key, value) in properties ?? new Dictionary<string, string>())
        {
            if (!Properties.Contains(key) || !Regex.IsMatch(value, @"^[A-Za-z0-9._\-]{0,32}$"))
                throw new ArgumentException("Statistics property not allowed: " + key);
            fields[key] = value;
        }
        return JsonSerializer.SerializeToUtf8Bytes(new Dictionary<string, object?>
        {
            ["api_key"] = projectKey, ["event"] = name, ["distinct_id"] = installId,
            ["properties"] = fields, ["timestamp"] = time.ToString("O")
        });
    }
}
