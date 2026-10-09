using System.Net;
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using TokenVault.Core;

namespace TokenVault.Launcher;

public sealed record InstallProgress(string Stage, double Fraction);

// Profile: the version id to launch. LoaderVersion: the loader build used. LoaderDirectory: Forge/NeoForge folder or "".
public sealed record InstalledProfile(string Profile, string? LoaderVersion, string LoaderDirectory);

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
        "libraries.minecraft.net", "resources.download.minecraft.net", "maven.fabricmc.net", "meta.fabricmc.net",
        "meta.quiltmc.org", "maven.quiltmc.org", "maven.minecraftforge.net", "files.minecraftforge.net", "maven.neoforged.net"
    };

    public static readonly string[] Loaders = ["vanilla", "fabric", "quilt", "forge", "neoforge"];

    public static string LoaderName(string loader) => loader switch
    {
        "fabric" => "Fabric", "quilt" => "Quilt", "forge" => "Forge", "neoforge" => "NeoForge", _ => "Vanilla"
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

    // Installs (if needed) Minecraft c.MinecraftVersion with c.Loader. Fast when everything is already installed.
    // Forge and NeoForge run their own installer, inside the game sandbox, into a folder of their own.
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    public async Task<InstalledProfile> EnsureAsync(Configuration c, string? loaderVersion, GameSandbox? sandbox,
        IProgress<InstallProgress>? progress, CancellationToken ct)
    {
        string root = Configuration.Expand(c.MinecraftDirectory);
        string minecraft = c.MinecraftVersion;
        if (!Configuration.IsVersionId(minecraft)) throw new UserVisibleException("Invalid Minecraft version.");
        Directory.CreateDirectory(root);
        await EnsureMinecraftAsync(root, minecraft, progress, ct);
        switch (c.Loader)
        {
            case "vanilla":
                return new(minecraft, null, "");
            case "fabric":
                loaderVersion ??= await LatestFabricAsync(minecraft, ct);
                return new(await EnsureProfileAsync(root, "Fabric", $"fabric-loader-{loaderVersion}-{minecraft}",
                    $"https://meta.fabricmc.net/v2/versions/loader/{minecraft}/{loaderVersion}/profile/json", "https://maven.fabricmc.net/", minecraft, progress, ct),
                    loaderVersion, "");
            case "quilt":
                loaderVersion ??= await LatestQuiltAsync(minecraft, ct);
                return new(await EnsureProfileAsync(root, "Quilt", $"quilt-loader-{loaderVersion}-{minecraft}",
                    $"https://meta.quiltmc.org/v3/versions/loader/{minecraft}/{loaderVersion}/profile/json", "https://maven.quiltmc.org/repository/release/", minecraft, progress, ct),
                    loaderVersion, "");
            case "forge" or "neoforge":
                if (sandbox is null) throw new UserVisibleException("Installing " + LoaderName(c.Loader) + " needs the sandbox.");
                loaderVersion ??= c.Loader == "forge" ? await LatestForgeAsync(minecraft, ct) : await LatestNeoForgeAsync(minecraft, ct);
                return await EnsureForgeAsync(c, root, loaderVersion, sandbox, progress, ct);
            default:
                throw new UserVisibleException("Unknown mod loader: " + c.Loader);
        }
    }

    public async Task<List<string>> ReleasesAsync(CancellationToken ct)
    {
        var manifest = await JsonAsync(VersionManifest, ct);
        return manifest["versions"]!.AsArray()
            .Where(v => v?["type"]?.GetValue<string>() == "release")
            .Select(v => v!["id"]!.GetValue<string>())
            .TakeWhile(id => id != "1.7.10") // 1.8 and later
            .ToList();
    }

    public async Task<string> LatestFabricAsync(string minecraft, CancellationToken ct)
    {
        var list = await JsonAsync($"https://meta.fabricmc.net/v2/versions/loader/{minecraft}", ct, missing: $"Fabric doesn't support Minecraft {minecraft}.");
        return list.AsArray().Select(n => n?["loader"]).FirstOrDefault(l => l?["stable"]?.GetValue<bool>() == true)?["version"]?.GetValue<string>()
            ?? throw new UserVisibleException($"Fabric has no stable loader for Minecraft {minecraft} yet.");
    }

    public async Task<string> LatestQuiltAsync(string minecraft, CancellationToken ct)
    {
        var list = await JsonAsync($"https://meta.quiltmc.org/v3/versions/loader/{minecraft}", ct, missing: $"Quilt doesn't support Minecraft {minecraft}.");
        var versions = list.AsArray().Select(n => n?["loader"]?["version"]?.GetValue<string>()).OfType<string>().ToList();
        return versions.FirstOrDefault(v => !v.Contains("beta") && !v.Contains("pre")) ?? versions.FirstOrDefault()
            ?? throw new UserVisibleException($"Quilt doesn't support Minecraft {minecraft}.");
    }

    public async Task<string> LatestForgeAsync(string minecraft, CancellationToken ct)
    {
        var promotions = await JsonAsync("https://files.minecraftforge.net/net/minecraftforge/forge/promotions_slim.json", ct);
        string? version = promotions["promos"]?[minecraft + "-recommended"]?.GetValue<string>() ?? promotions["promos"]?[minecraft + "-latest"]?.GetValue<string>();
        return version is null ? throw new UserVisibleException($"Forge doesn't support Minecraft {minecraft}.") : minecraft + "-" + version;
    }

    public async Task<string> LatestNeoForgeAsync(string minecraft, CancellationToken ct)
    {
        // NeoForge numbers its builds after the Minecraft version: 1.21.1 -> 21.1.x, 26.1.2 -> 26.1.2.x. 1.20.1 was "forge".
        bool legacy = minecraft == "1.20.1";
        var list = await JsonAsync("https://maven.neoforged.net/api/maven/versions/releases/net/neoforged/" + (legacy ? "forge" : "neoforge"), ct);
        string[] parts = minecraft.Split('.');
        string prefix = legacy ? "1.20.1-" : parts[0] == "1" && parts.Length >= 2 ? $"{parts[1]}.{(parts.Length > 2 ? parts[2] : "0")}." : minecraft + ".";
        var versions = list["versions"]!.AsArray().Select(v => v!.GetValue<string>()).Where(v => v.StartsWith(prefix, StringComparison.Ordinal)).ToList();
        return versions.LastOrDefault(v => !v.Contains("beta") && !v.Contains("alpha")) ?? versions.LastOrDefault()
            ?? throw new UserVisibleException($"NeoForge doesn't support Minecraft {minecraft}.");
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
            if (!InstalledVersion.Allowed(node!["rules"])) continue;
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
        string component = SafeName(version["javaVersion"]?["component"]?.GetValue<string>() ?? "jre-legacy"); // pre-1.17: Java 8
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

    // Fabric and Quilt publish a ready-made version JSON whose libraries are plain Maven downloads.
    private async Task<string> EnsureProfileAsync(string root, string name, string id, string url, string defaultRepository, string minecraft,
        IProgress<InstallProgress>? progress, CancellationToken ct)
    {
        if (!Configuration.IsVersionId(id)) throw new UserVisibleException($"Invalid {name} loader version.");
        string profileFile = Under(root, $"versions/{id}/{id}.json");
        string marker = profileFile + ".complete";
        if (File.Exists(marker)) return id;
        progress?.Report(new($"Installing {name}…", 0));
        var profile = await JsonAsync(url, ct, missing: $"{name} doesn't support Minecraft {minecraft}.");
        if (profile["id"]?.GetValue<string>() != id || profile["inheritsFrom"]?.GetValue<string>() != minecraft)
            throw new UserVisibleException($"{name} returned an unexpected profile.");
        var files = new List<FileJob>();
        foreach (var node in profile["libraries"]!.AsArray())
        {
            string library = node!["name"]!.GetValue<string>();
            var repository = Url(node["url"] ?? JsonValue.Create(defaultRepository));
            string path = InstalledVersion.MavenPath(library);
            files.Add(new(new Uri(repository, path), Under(root, "libraries/" + path),
                node["sha1"] is JsonNode sha ? Sha1(sha) : null, Size(node["size"])));
        }
        Directory.CreateDirectory(Path.GetDirectoryName(profileFile)!);
        await File.WriteAllTextAsync(profileFile, profile.ToJsonString(), ct);
        await DownloadAllAsync(files, $"Installing {name}", progress, ct);
        await File.WriteAllTextAsync(marker, DateTimeOffset.UtcNow.ToString("O"), ct);
        return id;
    }

    // Forge/NeoForge: their official installer patches Minecraft with code that has to run. It runs inside the game
    // sandbox, writing only to its own folder (GameRoot/Loaders/...), never with this user's full rights.
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private async Task<InstalledProfile> EnsureForgeAsync(Configuration c, string root, string version, GameSandbox sandbox,
        IProgress<InstallProgress>? progress, CancellationToken ct)
    {
        string minecraft = c.MinecraftVersion, name = LoaderName(c.Loader);
        if (!Configuration.IsVersionId(version)) throw new UserVisibleException($"Invalid {name} version.");
        string folder = Path.Combine(AppPaths.GameRoot, "Loaders", $"{c.Loader}-{version}");
        string marker = Path.Combine(folder, ".tokenvault-installed");
        if (File.Exists(marker) && File.ReadAllText(marker).Trim() is var installed && Configuration.IsVersionId(installed) &&
            File.Exists(Path.Combine(folder, "versions", installed, installed + ".json")))
            return new(installed, version, folder);

        progress?.Report(new($"Installing {name} {version}…", 0));
        JavaLauncher.DeleteRun(folder); // an unfinished earlier attempt
        Directory.CreateDirectory(Path.Combine(folder, "versions", minecraft));
        Directory.CreateDirectory(Path.Combine(folder, "tmp"));
        // Files Token Vault provides are written before the sandbox can write the folder.
        await File.WriteAllTextAsync(Path.Combine(folder, "launcher_profiles.json"), "{\"profiles\":{}}", ct);
        foreach (string extension in new[] { ".json", ".jar" })
            File.Copy(Path.Combine(root, "versions", minecraft, minecraft + extension), Path.Combine(folder, "versions", minecraft, minecraft + extension));
        string group = c.Loader == "forge" ? "net/minecraftforge/forge" : minecraft == "1.20.1" ? "net/neoforged/forge" : "net/neoforged/neoforge";
        string artifact = group[(group.LastIndexOf('/') + 1)..];
        string host = c.Loader == "forge" ? "https://maven.minecraftforge.net/" : "https://maven.neoforged.net/releases/";
        var installerUrl = new Uri($"{host}{group}/{version}/{artifact}-{version}-installer.jar");
        string? sha1 = null;
        try { sha1 = (await TextAsync(new Uri(installerUrl + ".sha1"), ct)).Trim()[..40].ToLowerInvariant(); } catch (Exception ex) when (ex is UserVisibleException or ArgumentOutOfRangeException) { }
        string installer = Path.Combine(folder, "installer.jar");
        await DownloadAsync(new(installerUrl, installer, sha1 is not null && Regex.IsMatch(sha1, "^[0-9a-f]{40}$") ? sha1 : null, 0), ct);

        string java = JavaLocator.Find(c) ?? throw new UserVisibleException("Java isn't installed yet. Press Play again.");
        sandbox.GrantRead(JavaLocator.Home(java));
        sandbox.GrantWrite(folder);
        string log = Path.Combine(AppPaths.Run, "installer-" + Guid.NewGuid().ToString("N") + ".log");
        Directory.CreateDirectory(AppPaths.Run);
        using var output = new FileStream(log, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.ReadWrite, 4096, FileOptions.DeleteOnClose);
        var environment = JavaLauncher.SandboxEnvironment(Path.Combine(folder, "tmp"));
        progress?.Report(new($"Running the {name} installer in the sandbox (this can take a few minutes)…", 0.5));
        int code;
        using (var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct))
        {
            timeout.CancelAfter(TimeSpan.FromMinutes(20));
            using var process = sandbox.Start(java, ["-XX:-UsePerfData", "-Djava.awt.headless=true", "-Duser.home=" + folder,
                "-Djava.io.tmpdir=" + Path.Combine(folder, "tmp"), "-jar", installer, "--installClient", folder],
                folder, environment, allowClipboard: false, output.SafeFileHandle);
            try { code = await process.WaitForExitAsync(timeout.Token); }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested) { code = -1; }
        }
        // The installer adds exactly one version folder next to the vanilla one.
        var profiles = Directory.EnumerateDirectories(Path.Combine(folder, "versions")).Select(Path.GetFileName).OfType<string>()
            .Where(v => v != minecraft && Configuration.IsVersionId(v) && File.Exists(Path.Combine(folder, "versions", v, v + ".json"))).ToList();
        if (code != 0 || profiles.Count != 1)
        {
            output.Position = Math.Max(0, output.Length - 4096);
            string tail = new StreamReader(output).ReadToEnd();
            string last = tail.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).LastOrDefault(l => !l.StartsWith("at ", StringComparison.Ordinal)) ?? "";
            throw new UserVisibleException($"The {name} installer failed (exit code {code}). {new string(last.Where(ch => !char.IsControl(ch)).Take(200).ToArray())}");
        }
        File.Delete(marker);
        await File.WriteAllTextAsync(marker, profiles[0], ct);
        return new(profiles[0], version, folder);
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

    private async Task<JsonNode> JsonAsync(string url, CancellationToken ct, string? missing = null) =>
        JsonNode.Parse(await TextAsync(new Uri(url), ct, missing)) ?? throw new InvalidDataException("Empty metadata.");

    private async Task<string> TextAsync(Uri uri, CancellationToken ct, string? missing = null)
    {
        CheckHost(uri);
        using var response = await http.GetAsync(uri, ct);
        if (missing is not null && response.StatusCode is HttpStatusCode.NotFound or HttpStatusCode.BadRequest) throw new UserVisibleException(missing);
        if (!response.IsSuccessStatusCode) throw new UserVisibleException($"Could not reach {uri.Host} ({(int)response.StatusCode}). Check your internet connection.");
        string text = await response.Content.ReadAsStringAsync(ct);
        if (missing is not null && text.Trim() is "[]" or "") throw new UserVisibleException(missing);
        return text;
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
