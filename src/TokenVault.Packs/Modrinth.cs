using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;
using TokenVault.Core;

namespace TokenVault.Packs;

public sealed record ModrinthHit(string ProjectId, string Slug, string Title, string Description, string Author, long Downloads, Uri? Icon);

// One file to install: always a .jar from Modrinth's CDN with its published SHA-512.
public sealed record ModrinthFile(string ProjectId, string Title, string FileName, Uri Url, string Sha512, long Size);

// Finds mods on Modrinth (api.modrinth.com, no account or key needed) for an instance's Minecraft version and loader,
// and works out which files to download, including required dependencies such as Fabric API. Everything the API
// returns is treated as untrusted: ids are checked before they go into a URL, files must be .jar downloads from
// cdn.modrinth.com with a SHA-512, and responses are size-limited. Downloading is PackImporter.InstallModAsync.
public sealed class ModrinthClient(HttpClient http)
{
    private const string Api = "https://api.modrinth.com/v2/";
    private const long MaxResponseBytes = 4 * 1024 * 1024;
    private const long MaxIconBytes = 256 * 1024;
    private const int MaxFiles = 30; // a mod and its dependency chain
    private static readonly Regex Id = new("^[A-Za-z0-9_-]{1,64}$", RegexOptions.CultureInvariant);
    private static readonly Regex Hex512 = new("^[0-9a-fA-F]{128}$", RegexOptions.CultureInvariant);

    public static HttpClient CreateHttp(string userAgent)
    {
        var client = new HttpClient(new SocketsHttpHandler
        {
            AllowAutoRedirect = false, UseCookies = false, AutomaticDecompression = DecompressionMethods.All,
            ConnectTimeout = TimeSpan.FromSeconds(15)
        }) { Timeout = TimeSpan.FromMinutes(10) };
        client.DefaultRequestHeaders.UserAgent.ParseAdd(userAgent); // Modrinth asks every app to identify itself
        return client;
    }

    // Modrinth's loader names. Quilt also runs Fabric mods. Vanilla loads no mods at all.
    public static string[] LoadersFor(string loader) => loader switch
    {
        "quilt" => ["quilt", "fabric"],
        "fabric" or "forge" or "neoforge" => [loader],
        _ => []
    };

    public async Task<IReadOnlyList<ModrinthHit>> SearchAsync(string query, string minecraft, string loader, CancellationToken ct)
    {
        string[] loaders = LoadersFor(loader);
        if (loaders.Length == 0 || !Configuration.IsVersionId(minecraft)) return [];
        string facets = JsonSerializer.Serialize(new[]
        {
            new[] { "project_type:mod" }, new[] { "versions:" + minecraft }, loaders.Select(l => "categories:" + l).ToArray()
        });
        using var json = await GetJsonAsync($"search?limit=25&index={(query.Trim().Length == 0 ? "downloads" : "relevance")}&query={Uri.EscapeDataString(query.Trim())}&facets={Uri.EscapeDataString(facets)}", ct);
        var hits = new List<ModrinthHit>();
        if (!json.RootElement.TryGetProperty("hits", out var array) || array.ValueKind != JsonValueKind.Array) return hits;
        foreach (var hit in array.EnumerateArray())
        {
            string? id = Text(hit, "project_id");
            if (id is null || !Id.IsMatch(id)) continue;
            Uri? icon = Uri.TryCreate(Text(hit, "icon_url"), UriKind.Absolute, out var u) && IsCdn(u) ? u : null;
            hits.Add(new(id, Text(hit, "slug") ?? "", Clean(Text(hit, "title") ?? id, 80), Clean(Text(hit, "description") ?? "", 200), Clean(Text(hit, "author") ?? "", 40),
                hit.TryGetProperty("downloads", out var d) && d.TryGetInt64(out long n) ? n : 0, icon));
        }
        return hits;
    }

    // The newest compatible file of a project, then the required dependencies' files. Projects already installed are
    // left out, along with their dependencies: those in skip (installed from Modrinth) and those whose slug matches the
    // id of a mod already in the folder (installed some other way, e.g. by a modpack; Modrinth slugs usually are mod ids).
    public async Task<IReadOnlyList<ModrinthFile>> ResolveAsync(string projectId, string minecraft, string loader, IReadOnlySet<string> skip,
        IReadOnlySet<string> installedModIds, CancellationToken ct)
    {
        string[] loaders = LoadersFor(loader);
        if (loaders.Length == 0) throw new UserVisibleException("Vanilla Minecraft doesn't load mods. Make a Fabric, Quilt, Forge or NeoForge instance.");
        var files = new List<ModrinthFile>();
        var seen = new HashSet<string>(skip, StringComparer.Ordinal);
        var pending = new Queue<(string? Project, string? Version)>([(projectId, null)]);
        bool first = true;
        while (pending.TryDequeue(out var next) && files.Count < MaxFiles)
        {
            if (next.Project is { } p && seen.Contains(p)) { first = false; continue; }
            JsonElement? version = next.Version is { } v && Id.IsMatch(v) ? await VersionAsync(v, ct) : null;
            if (version is { } pinned && !Supports(pinned, minecraft, loaders)) version = null;
            string? project = next.Project ?? (version is { } found ? Text(found, "project_id") : null);
            if (project is null || !Id.IsMatch(project)) { first = false; continue; }
            version ??= await NewestAsync(project, minecraft, loaders, ct);
            if (version is not { } chosen)
            {
                if (first) throw new UserVisibleException($"This mod has no version for Minecraft {minecraft} with {LoaderTitle(loader)}.");
                throw new UserVisibleException($"A mod it needs has no version for Minecraft {minecraft} with {LoaderTitle(loader)}.");
            }
            bool root = first;
            first = false;
            if (!seen.Add(project)) continue;
            var (title, slug) = await ProjectAsync(project, ct);
            if (!root && installedModIds.Contains(slug)) continue;
            files.Add(PrimaryFile(chosen, project, title));
            if (chosen.TryGetProperty("dependencies", out var dependencies) && dependencies.ValueKind == JsonValueKind.Array)
                foreach (var dependency in dependencies.EnumerateArray())
                    if (Text(dependency, "dependency_type") == "required")
                        pending.Enqueue((Text(dependency, "project_id"), Text(dependency, "version_id")));
        }
        return files;
    }

    public async Task<byte[]?> IconAsync(Uri icon, CancellationToken ct)
    {
        if (!IsCdn(icon)) return null;
        using var response = await http.GetAsync(icon, HttpCompletionOption.ResponseHeadersRead, ct);
        if (!response.IsSuccessStatusCode) return null;
        await using var body = await response.Content.ReadAsStreamAsync(ct);
        using var buffer = new MemoryStream();
        try { await SafeFiles.CopyBoundedAsync(body, buffer, MaxIconBytes, ct); }
        catch (UserVisibleException) { return null; }
        return buffer.ToArray();
    }

    private async Task<JsonElement?> NewestAsync(string project, string minecraft, string[] loaders, CancellationToken ct)
    {
        string query = $"project/{project}/version?loaders={Uri.EscapeDataString(JsonSerializer.Serialize(loaders))}&game_versions={Uri.EscapeDataString(JsonSerializer.Serialize(new[] { minecraft }))}";
        using var json = await GetJsonAsync(query, ct);
        if (json.RootElement.ValueKind != JsonValueKind.Array) return null;
        var versions = json.RootElement.EnumerateArray().Where(v => Supports(v, minecraft, loaders)).ToList();
        // Newest first; a release beats a newer beta.
        var best = versions.FirstOrDefault(v => Text(v, "version_type") == "release");
        return (best.ValueKind == JsonValueKind.Object ? best : versions.FirstOrDefault()) is { ValueKind: JsonValueKind.Object } found ? found.Clone() : null;
    }

    private async Task<JsonElement?> VersionAsync(string version, CancellationToken ct)
    {
        try
        {
            using var json = await GetJsonAsync("version/" + version, ct);
            return json.RootElement.ValueKind == JsonValueKind.Object ? json.RootElement.Clone() : null;
        }
        catch (UserVisibleException) { return null; } // a dependency pinned to a deleted version: fall back to the newest
    }

    private async Task<(string Title, string Slug)> ProjectAsync(string project, CancellationToken ct)
    {
        try
        {
            using var json = await GetJsonAsync("project/" + project, ct);
            return (Clean(Text(json.RootElement, "title") ?? project, 80), Text(json.RootElement, "slug") ?? "");
        }
        catch (UserVisibleException) { return (project, ""); }
    }

    private static bool Supports(JsonElement version, string minecraft, string[] loaders) =>
        Strings(version, "game_versions").Contains(minecraft) && Strings(version, "loaders").Any(loaders.Contains);

    private static ModrinthFile PrimaryFile(JsonElement version, string project, string title)
    {
        if (!version.TryGetProperty("files", out var files) || files.ValueKind != JsonValueKind.Array)
            throw new UserVisibleException($"{title} has no downloadable file on Modrinth.");
        var list = files.EnumerateArray().ToList();
        var file = list.FirstOrDefault(f => f.TryGetProperty("primary", out var p) && p.ValueKind == JsonValueKind.True);
        if (file.ValueKind != JsonValueKind.Object) file = list.FirstOrDefault();
        string name = SafeFiles.FileName(Text(file, "filename") ?? "");
        string? sha512 = file.ValueKind == JsonValueKind.Object && file.TryGetProperty("hashes", out var hashes) ? Text(hashes, "sha512") : null;
        long size = file.ValueKind == JsonValueKind.Object && file.TryGetProperty("size", out var s) && s.TryGetInt64(out long n) ? n : 0;
        if (!Uri.TryCreate(Text(file, "url"), UriKind.Absolute, out var url) || !IsCdn(url) || sha512 is null || !Hex512.IsMatch(sha512) ||
            !PackImporter.IsModFile(name) || size is <= 0 or > SafeFiles.MaxFileBytes)
            throw new UserVisibleException($"Modrinth's file for {title} isn't a checksummed .jar from its own servers, so Token Vault won't install it.");
        return new(project, title, name, url, sha512.ToLowerInvariant(), size);
    }

    private async Task<JsonDocument> GetJsonAsync(string path, CancellationToken ct)
    {
        using var response = await http.GetAsync(Api + path, HttpCompletionOption.ResponseHeadersRead, ct);
        if (response.StatusCode == HttpStatusCode.TooManyRequests) throw new UserVisibleException("Modrinth asked us to slow down. Try again in a minute.");
        if (!response.IsSuccessStatusCode) throw new UserVisibleException($"Modrinth answered {(int)response.StatusCode}.");
        await using var body = await response.Content.ReadAsStreamAsync(ct);
        using var buffer = new MemoryStream();
        await SafeFiles.CopyBoundedAsync(body, buffer, MaxResponseBytes, ct);
        buffer.Position = 0;
        try { return await JsonDocument.ParseAsync(buffer, cancellationToken: ct); }
        catch (JsonException) { throw new UserVisibleException("Modrinth sent something that isn't valid JSON."); }
    }

    public static bool IsCdn(Uri url) => url.Scheme == "https" && url.IsDefaultPort && url.UserInfo.Length == 0 &&
        url.Host.Equals("cdn.modrinth.com", StringComparison.OrdinalIgnoreCase);

    private static string LoaderTitle(string loader) => TokenVault.Launcher.GameInstaller.LoaderName(loader);

    private static string? Text(JsonElement element, string name) =>
        element.ValueKind == JsonValueKind.Object && element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    private static HashSet<string> Strings(JsonElement element, string name) =>
        element.TryGetProperty(name, out var array) && array.ValueKind == JsonValueKind.Array
            ? array.EnumerateArray().Where(e => e.ValueKind == JsonValueKind.String).Select(e => e.GetString()!).ToHashSet(StringComparer.Ordinal)
            : [];

    // Text shown in the window: single line, no control characters, bounded length.
    private static string Clean(string text, int max)
    {
        string flat = new(text.Select(c => char.IsControl(c) ? ' ' : c).ToArray());
        flat = Regex.Replace(flat, @"\s+", " ").Trim();
        return flat.Length <= max ? flat : flat[..(max - 1)] + "…";
    }
}
