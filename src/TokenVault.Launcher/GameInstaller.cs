using System.Net;
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using TokenVault.Core;

namespace TokenVault.Launcher;

public sealed record InstallProgress(string Stage, double Fraction);

// Installs Minecraft, its Java runtime and a Fabric loader into Token Vault's own folder, the way the official
// launcher would. Every file comes over HTTPS from Mojang or Fabric and is checked against the published SHA-1.
// The game sandbox can only READ this folder, so nothing here can be altered by a mod.
public sealed class GameInstaller(HttpClient http)
{
    private const string VersionManifest = "https://piston-meta.mojang.com/mc/game/version_manifest_v2.json";
    private const string JavaRuntimes = "https://launchermeta.mojang.com/v1/products/java-runtime/2ec0cc96c44e5a76b9c8b7c39df7210883d12871/all.json";
    private static readonly HashSet<string> Hosts = new(StringComparer.OrdinalIgnoreCase)
    {
        "piston-meta.mojang.com", "piston-data.mojang.com", "launchermeta.mojang.com", "launcher.mojang.com",
        "libraries.minecraft.net", "resources.download.minecraft.net", "maven.fabricmc.net", "meta.fabricmc.net"
    };

    public static HttpClient CreateHttp()
    {
        var client = new HttpClient(new SocketsHttpHandler
        {
            AllowAutoRedirect = false, UseCookies = false, AutomaticDecompression = DecompressionMethods.All,
            MaxConnectionsPerServer = 16, ConnectTimeout = TimeSpan.FromSeconds(20)
        }) { Timeout = TimeSpan.FromMinutes(10) };
        client.DefaultRequestHeaders.UserAgent.ParseAdd("TokenVault/1.0");
        return client;
    }

    // Returns the Fabric profile id to launch. Fast when everything is already installed.
    public async Task<string> EnsureAsync(Configuration c, string? loaderVersion, IProgress<InstallProgress>? progress, CancellationToken ct)
    {
        string root = Configuration.Expand(c.MinecraftDirectory);
        Directory.CreateDirectory(root);
        await EnsureMinecraftAsync(root, c.MinecraftVersion, progress, ct);
        loaderVersion ??= await LatestFabricAsync(c.MinecraftVersion, ct);
        return await EnsureFabricAsync(root, c.MinecraftVersion, loaderVersion, progress, ct);
    }

    public async Task<string> LatestFabricAsync(string minecraft, CancellationToken ct)
    {
        var list = await JsonAsync($"https://meta.fabricmc.net/v2/versions/loader/{minecraft}", ct);
        return list.AsArray().Select(n => n?["loader"]).FirstOrDefault(l => l?["stable"]?.GetValue<bool>() == true)?["version"]?.GetValue<string>()
            ?? throw new UserVisibleException($"Fabric has no stable loader for Minecraft {minecraft} yet.");
    }

    private async Task EnsureMinecraftAsync(string root, string id, IProgress<InstallProgress>? progress, CancellationToken ct)
    {
        string marker = Path.Combine(root, "versions", id, ".tokenvault-complete");
        if (File.Exists(marker)) return;
        progress?.Report(new($"Downloading Minecraft {id}…", 0));
        var manifest = await JsonAsync(VersionManifest, ct);
        var entry = manifest["versions"]!.AsArray().FirstOrDefault(v => v?["id"]?.GetValue<string>() == id)
            ?? throw new UserVisibleException($"Mojang does not list Minecraft {id}.");
        string versionFile = Under(root, $"versions/{id}/{id}.json");
        await DownloadAsync(new(Url(entry["url"]), versionFile, Sha1(entry["sha1"]), 0), ct);
        var version = JsonNode.Parse(await File.ReadAllTextAsync(versionFile, ct))!;

        var files = new List<FileJob>();
        var client = version["downloads"]!["client"]!;
        files.Add(new(Url(client["url"]), Under(root, $"versions/{id}/{id}.jar"), Sha1(client["sha1"]), Size(client["size"])));
        foreach (var node in version["libraries"]!.AsArray())
        {
            if (!InstalledFabric.Allowed(node!["rules"])) continue;
            if (node["downloads"]?["artifact"] is JsonObject artifact)
                files.Add(new(Url(artifact["url"]), Under(root, "libraries/" + artifact["path"]!.GetValue<string>()), Sha1(artifact["sha1"]), Size(artifact["size"])));
            if (node["natives"]?["windows"] is JsonNode native &&
                node["downloads"]?["classifiers"]?[native.GetValue<string>().Replace("${arch}", "64", StringComparison.Ordinal)] is JsonObject classifier)
                files.Add(new(Url(classifier["url"]), Under(root, "libraries/" + classifier["path"]!.GetValue<string>()), Sha1(classifier["sha1"]), Size(classifier["size"])));
        }
        var assetIndex = version["assetIndex"]!;
        string indexFile = Under(root, $"assets/indexes/{SafeName(assetIndex["id"]!.GetValue<string>())}.json");
        await DownloadAsync(new(Url(assetIndex["url"]), indexFile, Sha1(assetIndex["sha1"]), Size(assetIndex["size"])), ct);
        foreach (var (_, value) in JsonNode.Parse(await File.ReadAllTextAsync(indexFile, ct))!["objects"]!.AsObject())
        {
            string hash = Sha1(value!["hash"]);
            files.Add(new(new Uri($"https://resources.download.minecraft.net/{hash[..2]}/{hash}"),
                Under(root, $"assets/objects/{hash[..2]}/{hash}"), hash, Size(value["size"])));
        }
        string component = SafeName(version["javaVersion"]!["component"]!.GetValue<string>());
        var runtimes = await JsonAsync(JavaRuntimes, ct);
        var runtime = runtimes["windows-x64"]?[component]?.AsArray().FirstOrDefault()?["manifest"]
            ?? throw new UserVisibleException($"Mojang has no Windows Java runtime '{component}'.");
        string runtimeManifest = Under(root, $"runtime/{component}.manifest.json");
        await DownloadAsync(new(Url(runtime["url"]), runtimeManifest, Sha1(runtime["sha1"]), 0), ct);
        string javaHome = $"runtime/{component}/windows-x64/{component}";
        foreach (var (path, value) in JsonNode.Parse(await File.ReadAllTextAsync(runtimeManifest, ct))!["files"]!.AsObject())
        {
            string target = Under(root, javaHome + "/" + path);
            if (value!["type"]?.GetValue<string>() == "directory") { Directory.CreateDirectory(target); continue; }
            if (value["type"]?.GetValue<string>() != "file") continue; // links are not used on Windows
            var raw = value["downloads"]!["raw"]!;
            files.Add(new(Url(raw["url"]), target, Sha1(raw["sha1"]), Size(raw["size"])));
        }
        await DownloadAllAsync(files, $"Downloading Minecraft {id} and Java", progress, ct);
        await File.WriteAllTextAsync(marker, DateTimeOffset.UtcNow.ToString("O"), ct);
    }

    private async Task<string> EnsureFabricAsync(string root, string minecraft, string loader, IProgress<InstallProgress>? progress, CancellationToken ct)
    {
        if (!Regex.IsMatch(loader, @"^[0-9A-Za-z.+\-]{1,40}$")) throw new UserVisibleException("Invalid Fabric loader version.");
        string id = $"fabric-loader-{loader}-{minecraft}";
        string profileFile = Under(root, $"versions/{id}/{id}.json");
        string marker = profileFile + ".complete";
        if (File.Exists(marker)) return id;
        progress?.Report(new($"Installing Fabric {loader}…", 0));
        var profile = await JsonAsync($"https://meta.fabricmc.net/v2/versions/loader/{minecraft}/{loader}/profile/json", ct);
        if (profile["id"]?.GetValue<string>() != id || profile["inheritsFrom"]?.GetValue<string>() != minecraft)
            throw new UserVisibleException("Fabric returned an unexpected profile.");
        var files = new List<FileJob>();
        foreach (var node in profile["libraries"]!.AsArray())
        {
            string name = node!["name"]!.GetValue<string>();
            var repository = Url(node["url"] ?? JsonValue.Create("https://maven.fabricmc.net/"));
            string path = InstalledFabric.MavenPath(name);
            files.Add(new(new Uri(repository, path), Under(root, "libraries/" + path),
                node["sha1"] is JsonNode sha ? Sha1(sha) : null, Size(node["size"])));
        }
        Directory.CreateDirectory(Path.GetDirectoryName(profileFile)!);
        await File.WriteAllTextAsync(profileFile, profile.ToJsonString(), ct);
        await DownloadAllAsync(files, $"Installing Fabric {loader}", progress, ct);
        await File.WriteAllTextAsync(marker, DateTimeOffset.UtcNow.ToString("O"), ct);
        return id;
    }

    private sealed record FileJob(Uri Url, string Path, string? Sha1, long Size);

    private async Task DownloadAllAsync(List<FileJob> files, string stage, IProgress<InstallProgress>? progress, CancellationToken ct)
    {
        files = files.DistinctBy(f => f.Path, StringComparer.OrdinalIgnoreCase).ToList();
        long total = Math.Max(1, files.Sum(f => f.Size)), done = 0;
        using var gate = new SemaphoreSlim(12);
        var lastReport = DateTime.MinValue;
        await Task.WhenAll(files.Select(async file =>
        {
            await gate.WaitAsync(ct);
            try { await DownloadAsync(file, ct); }
            finally { gate.Release(); }
            long now = Interlocked.Add(ref done, file.Size);
            if (DateTime.UtcNow - lastReport > TimeSpan.FromMilliseconds(150))
            {
                lastReport = DateTime.UtcNow;
                progress?.Report(new($"{stage} — {now / 1048576} of {total / 1048576} MB", (double)now / total));
            }
        }));
        progress?.Report(new(stage, 1));
    }

    private async Task DownloadAsync(FileJob job, CancellationToken ct)
    {
        if (File.Exists(job.Path) && job.Sha1 is not null && (job.Size == 0 || new FileInfo(job.Path).Length == job.Size) &&
            await HashFileAsync(job.Path, ct) == job.Sha1) return;
        CheckHost(job.Url);
        Directory.CreateDirectory(Path.GetDirectoryName(job.Path)!);
        string part = job.Path + "." + Guid.NewGuid().ToString("N")[..8] + ".part";
        try
        {
            using (var response = await http.GetAsync(job.Url, HttpCompletionOption.ResponseHeadersRead, ct))
            {
                if (!response.IsSuccessStatusCode) throw new UserVisibleException($"Download failed ({(int)response.StatusCode}) from {job.Url.Host}. Check your internet connection.");
                await using var body = await response.Content.ReadAsStreamAsync(ct);
                await using var output = new FileStream(part, FileMode.CreateNew, FileAccess.Write, FileShare.None);
                using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA1);
                byte[] buffer = new byte[81920];
                long length = 0, limit = job.Size > 0 ? job.Size : 1L << 30;
                int read;
                while ((read = await body.ReadAsync(buffer, ct)) > 0)
                {
                    length += read;
                    if (length > limit) throw new UserVisibleException("A download was larger than Mojang/Fabric said it would be.");
                    sha.AppendData(buffer, 0, read);
                    await output.WriteAsync(buffer.AsMemory(0, read), ct);
                }
                if (job.Sha1 is not null && Convert.ToHexString(sha.GetHashAndReset()).ToLowerInvariant() != job.Sha1)
                    throw new UserVisibleException($"A downloaded file from {job.Url.Host} failed its checksum. Nothing was installed from it; try again.");
            }
            File.Move(part, job.Path, overwrite: true);
        }
        finally { File.Delete(part); }
    }

    private async Task<JsonNode> JsonAsync(string url, CancellationToken ct)
    {
        var uri = new Uri(url);
        CheckHost(uri);
        using var response = await http.GetAsync(uri, ct);
        if (!response.IsSuccessStatusCode) throw new UserVisibleException($"Could not reach {uri.Host} ({(int)response.StatusCode}). Check your internet connection.");
        return JsonNode.Parse(await response.Content.ReadAsStringAsync(ct)) ?? throw new InvalidDataException("Empty metadata.");
    }

    private static async Task<string> HashFileAsync(string path, CancellationToken ct)
    {
        await using var stream = File.OpenRead(path);
        return Convert.ToHexString(await SHA1.HashDataAsync(stream, ct)).ToLowerInvariant();
    }

    private static void CheckHost(Uri url)
    {
        if (url.Scheme != "https" || !url.IsDefaultPort || url.UserInfo.Length > 0 || !Hosts.Contains(url.Host))
            throw new UserVisibleException("Refusing to download game files from " + url.Host + ".");
    }

    private static Uri Url(JsonNode? node)
    {
        var url = new Uri(node!.GetValue<string>(), UriKind.Absolute);
        CheckHost(url);
        return url;
    }

    private static string Sha1(JsonNode? node) =>
        node?.GetValue<string>() is { } s && Regex.IsMatch(s, "^[0-9a-f]{40}$") ? s : throw new InvalidDataException("Invalid SHA-1 in metadata.");
    private static long Size(JsonNode? node) => node is null ? 0 : Math.Max(0, node.GetValue<long>());
    private static string SafeName(string s) =>
        Regex.IsMatch(s, @"^[0-9A-Za-z._\-]{1,64}$") && s is not ("." or "..") ? s : throw new InvalidDataException("Invalid name in metadata.");

    // Metadata paths must stay inside the install folder.
    public static string Under(string root, string relative)
    {
        string[] parts = relative.Replace('\\', '/').Split('/');
        if (parts.Any(p => p.Length == 0 || p is "." or ".." || p.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 || p.EndsWith('.') || p.EndsWith(' ')))
            throw new InvalidDataException("Unsafe path in game metadata.");
        string full = Path.GetFullPath(Path.Combine([root, .. parts]));
        if (!SandboxPolicy.IsWithin(full, root)) throw new InvalidDataException("Path escapes the install folder.");
        return full;
    }
}
