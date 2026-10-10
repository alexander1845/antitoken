using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using SharpCompress.Archives;
using TokenVault.Core;
using TokenVault.Launcher;

namespace TokenVault.Packs;

// Imports modpacks into a NEW instance folder, set up for the Minecraft version and loader the pack declares. Supported:
//   Modrinth .mrpack · CurseForge .zip (manifest.json) · Prism/MultiMC exports (mmc-pack.json / instance.cfg)
//   any .zip / .7z / .rar / .tar(.gz) or folder containing mods or a .minecraft-style folder · single .jar mods.
// Everything is unpacked by Token Vault into a folder the sandbox has never had access to, then handed to the
// sandbox at launch. Downloads are HTTPS-only, from the hosts each format allows, and hash-checked when the
// pack provides hashes. Mods still only ever run inside the sandbox.
public sealed class PackImporter(HttpClient http)
{
    // Bytes actually written by this import (archive entries can lie about their sizes). Shared by parallel downloads.
    private long written;

    public static readonly string[] Extensions = [".mrpack", ".zip", ".7z", ".rar", ".tar", ".gz", ".tgz", ".jar"];
    public const string Filter = "Modpacks and mods|*.mrpack;*.zip;*.7z;*.rar;*.tar;*.gz;*.tgz;*.jar|All files|*.*";

    private static readonly string[] ModrinthHosts = ["cdn.modrinth.com", "github.com", "raw.githubusercontent.com", "gitlab.com"];
    private static readonly string[] RedirectSuffixes = [".modrinth.com", ".githubusercontent.com", ".github.com", ".gitlab.com", ".forgecdn.net", ".curseforge.com"];

    public static HttpClient CreateHttp()
    {
        var client = new HttpClient(new SocketsHttpHandler
        {
            AllowAutoRedirect = false, UseCookies = false, AutomaticDecompression = DecompressionMethods.All,
            ConnectTimeout = TimeSpan.FromSeconds(20)
        }) { Timeout = TimeSpan.FromMinutes(10) };
        client.DefaultRequestHeaders.UserAgent.ParseAdd("TokenVault/1.0 (modpack import)");
        return client;
    }

    public async Task<Instance> ImportAsync(string path, IProgress<InstallProgress>? progress, CancellationToken ct)
    {
        progress?.Report(new("Reading " + Path.GetFileName(Path.TrimEndingDirectorySeparator(path)) + "…", 0));
        using var source = PackSource.Open(path);
        var instance = new Instance { Name = Path.GetFileNameWithoutExtension(Path.TrimEndingDirectorySeparator(path)) };
        // Read and check the pack BEFORE creating anything or downloading.
        var (kind, root) = Detect(source);
        InstanceStore.CreateFolder(instance);
        try
        {
            switch (kind)
            {
                case PackKind.Modrinth: await ModrinthAsync(source, root, instance, progress, ct); break;
                case PackKind.CurseForge: await CurseForgeAsync(source, root, instance, progress, ct); break;
                case PackKind.Prism: await PrismAsync(source, root, instance, progress, ct); break;
                default: await LooseAsync(source, root, instance, progress, ct); break;
            }
            if (instance.CountMods() == 0 && instance.Missing.Count == 0 && kind == PackKind.Loose)
                throw new UserVisibleException("No mods were found in " + Path.GetFileName(path) + ".");
            // Loose files don't say what they're for: read it from the mods themselves (newest loader build is used).
            if (kind == PackKind.Loose && ModInfo.Detect(instance.ModsDirectory) is { } detected)
                ApplyLoader(instance, detected.Minecraft, detected.Loader, null);
            return instance;
        }
        catch
        {
            try { InstanceStore.DeleteFolder(instance); } catch (IOException) { }
            throw;
        }
    }

    // Adds loose mod files to an existing instance. Only call while its game is closed.
    public static void AddMods(Instance instance, IEnumerable<string> jars)
    {
        Directory.CreateDirectory(instance.ModsDirectory);
        foreach (string jar in jars)
        {
            string target = SafeFiles.Under(instance.Directory, "mods/" + SafeFiles.FileName(jar));
            File.Delete(target); // removes anything (even a planted link) at that name
            using var input = File.OpenRead(jar);
            using var output = new FileStream(target, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            input.CopyTo(output);
        }
    }

    // Downloads one Modrinth file (see ModrinthClient.ResolveAsync) into an existing instance's mods folder and records
    // where it came from. Only call while its game is closed.
    public async Task InstallModAsync(Instance instance, ModrinthFile file, CancellationToken ct)
    {
        if (!ModrinthClient.IsCdn(file.Url) || !IsModFile(file.FileName))
            throw new UserVisibleException("Token Vault only installs .jar files from Modrinth's own servers.");
        Directory.CreateDirectory(instance.ModsDirectory);
        string target = SafeFiles.Under(instance.Directory, "mods/" + SafeFiles.FileName(file.FileName));
        await DownloadAsync(file.Url, target, file.Size, file.Sha512, null, ct);
        instance.ModrinthFiles[Path.GetFileName(target)] = file.ProjectId;
    }

    public static bool IsModFile(string path) => path.EndsWith(".jar", StringComparison.OrdinalIgnoreCase);

    // ---------- Detection

    internal enum PackKind { Modrinth, CurseForge, Prism, Loose }

    internal static (PackKind Kind, string Root) Detect(PackSource source)
    {
        PackEntry? Shallowest(Func<string, bool> name) => source.Entries.Where(e => name(Path.GetFileName(e.Path)))
            .OrderBy(e => e.Path.Count(c => c == '/')).FirstOrDefault();
        static string Dir(PackEntry e) => e.Path.Contains('/') ? e.Path[..(e.Path.LastIndexOf('/') + 1)] : "";

        if (Shallowest(n => n == "modrinth.index.json") is { } modrinth) return (PackKind.Modrinth, Dir(modrinth));
        if (Shallowest(n => n == "manifest.json") is { } manifest && IsCurseForge(source, manifest)) return (PackKind.CurseForge, Dir(manifest));
        if (Shallowest(n => n is "mmc-pack.json" or "instance.cfg") is { } prism) return (PackKind.Prism, Dir(prism));
        // Loose: a folder that has mods/ (possibly wrapped, e.g. "MyPack/.minecraft/mods/x.jar"), else bare .jar files.
        var mods = source.Entries.Where(e => IsModFile(e.Path) && ("/" + e.Path).Contains("/mods/", StringComparison.OrdinalIgnoreCase))
            .OrderBy(e => e.Path.Length).FirstOrDefault();
        if (mods is not null)
        {
            int at = ("/" + mods.Path).LastIndexOf("/mods/", StringComparison.OrdinalIgnoreCase);
            return (PackKind.Loose, mods.Path[..at]);
        }
        return (PackKind.Loose, "\0jars"); // marker: flatten every .jar into mods/
    }

    private static bool IsCurseForge(PackSource source, PackEntry manifest)
    {
        try
        {
            using var json = source.ReadJson(manifest);
            return json.RootElement.ValueKind == JsonValueKind.Object && json.RootElement.TryGetProperty("manifestType", out var type) &&
                type.ValueKind == JsonValueKind.String && type.GetString() == "minecraftModpack";
        }
        catch (UserVisibleException) { return false; }
    }

    // Sets the instance's Minecraft version and loader from what the pack declares. Loader versions are stored the way
    // GameInstaller expects them: Forge (and NeoForge for 1.20.1) as "<minecraft>-<build>", NeoForge otherwise as its own number.
    internal static void ApplyLoader(Instance instance, string? minecraft, string? loader, string? version)
    {
        if (minecraft is not null)
        {
            if (!Configuration.IsVersionId(minecraft)) throw new UserVisibleException("The pack names an invalid Minecraft version.");
            instance.MinecraftVersion = minecraft;
        }
        loader ??= "vanilla";
        if (!TokenVault.Launcher.GameInstaller.Loaders.Contains(loader))
            throw new UserVisibleException($"This pack uses {loader}, which Token Vault can't install.");
        if (version is not null && !Configuration.IsVersionId(version)) throw new UserVisibleException("The pack names an invalid loader version.");
        bool prefixed = loader == "forge" || (loader == "neoforge" && instance.MinecraftVersion == "1.20.1");
        instance.Loader = loader;
        instance.LoaderVersion = loader == "vanilla" || version is null ? null
            : prefixed && !version.StartsWith(instance.MinecraftVersion + "-", StringComparison.Ordinal) ? instance.MinecraftVersion + "-" + version
            : version;
    }

    // Loader ids as Modrinth, CurseForge and Prism name them.
    internal static string? LoaderId(string id) => id.ToLowerInvariant() switch
    {
        "fabric-loader" or "net.fabricmc.fabric-loader" or "fabric" => "fabric",
        "quilt-loader" or "org.quiltmc.quilt-loader" or "quilt" => "quilt",
        "forge" or "net.minecraftforge" => "forge",
        "neoforge" or "net.neoforged" => "neoforge",
        _ => null
    };

    // ---------- Modrinth (.mrpack)

    private async Task ModrinthAsync(PackSource source, string root, Instance instance, IProgress<InstallProgress>? progress, CancellationToken ct)
    {
        using var index = source.ReadJson(source.Get(root + "modrinth.index.json"));
        var r = index.RootElement;
        if (r.TryGetProperty("game", out var game) && game.GetString() != "minecraft") throw new UserVisibleException("This Modrinth pack is not for Minecraft.");
        var deps = r.GetProperty("dependencies");
        string? minecraft = null, loader = null, loaderVersion = null;
        foreach (var dep in deps.EnumerateObject())
        {
            if (dep.Name == "minecraft") minecraft = dep.Value.GetString();
            else if (LoaderId(dep.Name) is { } id) { loader = id; loaderVersion = dep.Value.GetString(); }
            else throw new UserVisibleException($"This pack needs {dep.Name}, which Token Vault can't install.");
        }
        ApplyLoader(instance, minecraft, loader, loaderVersion);
        instance.Source = "Modrinth";
        if (r.TryGetProperty("name", out var name) && name.GetString() is { Length: > 0 } n) instance.Name = n;

        var downloads = new List<(Uri Url, string Target, string? Sha512, string? Sha1, long Size)>();
        foreach (var file in r.GetProperty("files").EnumerateArray())
        {
            if (file.TryGetProperty("env", out var env) && env.TryGetProperty("client", out var client) && client.GetString() == "unsupported") continue;
            string target = SafeFiles.Under(instance.Directory, file.GetProperty("path").GetString()!);
            var hashes = file.GetProperty("hashes");
            string? sha512 = hashes.TryGetProperty("sha512", out var h5) ? h5.GetString() : null;
            string? sha1 = hashes.TryGetProperty("sha1", out var h1) ? h1.GetString() : null;
            if (sha512 is null && sha1 is null) throw new UserVisibleException("A Modrinth pack file has no checksum.");
            var url = file.GetProperty("downloads").EnumerateArray().Select(u => Uri.TryCreate(u.GetString(), UriKind.Absolute, out var x) ? x : null)
                .FirstOrDefault(u => u is not null && u.Scheme == "https" && ModrinthHosts.Contains(u.Host, StringComparer.OrdinalIgnoreCase))
                ?? throw new UserVisibleException("A Modrinth pack file has no download from an allowed site (Modrinth, GitHub, GitLab).");
            long size = file.TryGetProperty("fileSize", out var fs) && fs.TryGetInt64(out long s) ? s : 0;
            downloads.Add((url, target, sha512, sha1, size));
        }
        int done = 0;
        await ForEachAsync(downloads, 6, async d =>
        {
            await DownloadAsync(d.Url, d.Target, d.Size > 0 ? d.Size : SafeFiles.MaxFileBytes, d.Sha512, d.Sha1, ct);
            progress?.Report(new($"Downloading mods — {Interlocked.Increment(ref done)} of {downloads.Count}", (double)done / downloads.Count));
        }, ct);
        await CopyTreeAsync(source, root + "overrides/", instance.Directory, false, ct);
        await CopyTreeAsync(source, root + "client-overrides/", instance.Directory, false, ct);
    }

    // ---------- CurseForge (.zip with manifest.json)

    private async Task CurseForgeAsync(PackSource source, string root, Instance instance, IProgress<InstallProgress>? progress, CancellationToken ct)
    {
        using var manifest = source.ReadJson(source.Get(root + "manifest.json"));
        var r = manifest.RootElement;
        var mc = r.GetProperty("minecraft");
        string? loader = null, loaderVersion = null;
        // "forge-47.2.0", "neoforge-21.1.77", "fabric-0.16.9", "quilt-0.26.0"; the primary one wins.
        foreach (var entry in mc.GetProperty("modLoaders").EnumerateArray()
                     .OrderByDescending(l => l.TryGetProperty("primary", out var p) && p.ValueKind == JsonValueKind.True))
        {
            string id = entry.GetProperty("id").GetString() ?? "";
            int dash = id.IndexOf('-');
            if (dash > 0 && LoaderId(id[..dash]) is { } known) { loader = known; loaderVersion = id[(dash + 1)..]; break; }
            throw new UserVisibleException($"This pack uses {id}, which Token Vault can't install.");
        }
        ApplyLoader(instance, mc.GetProperty("version").GetString(), loader, loaderVersion);
        instance.Source = "CurseForge";
        if (r.TryGetProperty("name", out var name) && name.GetString() is { Length: > 0 } n) instance.Name = n;

        var files = r.GetProperty("files").EnumerateArray()
            .Where(f => !f.TryGetProperty("required", out var req) || req.ValueKind != JsonValueKind.False)
            .Select(f => (Project: f.GetProperty("projectID").GetInt64(), File: f.GetProperty("fileID").GetInt64())).ToList();
        int done = 0;
        var missing = new System.Collections.Concurrent.ConcurrentBag<MissingFile>();
        await ForEachAsync(files, 6, async f =>
        {
            try
            {
                // CurseForge's public download link redirects to its CDN; some authors disallow this, which then fails.
                var url = new Uri($"https://www.curseforge.com/api/v1/mods/{f.Project}/files/{f.File}/download");
                var (stream, final) = await OpenFollowingAsync(url, ct);
                await using (stream)
                {
                    string fileName = SafeFiles.FileName(Uri.UnescapeDataString(final.Segments[^1]));
                    string folder = fileName.EndsWith(".zip", StringComparison.OrdinalIgnoreCase) ? "resourcepacks/" : "mods/";
                    // CurseForge publishes no hash without an API key; these files are checked only by HTTPS.
                    await SaveAsync(stream, SafeFiles.Under(instance.Directory, folder + fileName), SafeFiles.MaxFileBytes, null, null, ct);
                }
            }
            catch (Exception ex) when (ex is HttpRequestException or UserVisibleException or IOException)
            {
                missing.Add(new MissingFile($"CurseForge project {f.Project}, file {f.File}", $"https://www.curseforge.com/projects/{f.Project}"));
            }
            progress?.Report(new($"Downloading mods — {Interlocked.Increment(ref done)} of {files.Count}", (double)done / files.Count));
        }, ct);
        instance.Missing = missing.ToList();
        string overrides = r.TryGetProperty("overrides", out var o) && o.GetString() is { Length: > 0 } od ? od.Trim('/') + "/" : "overrides/";
        await CopyTreeAsync(source, root + overrides, instance.Directory, false, ct);
    }

    // ---------- Prism Launcher / MultiMC export

    private async Task PrismAsync(PackSource source, string root, Instance instance, IProgress<InstallProgress>? progress, CancellationToken ct)
    {
        string? minecraft = null, loader = null, loaderVersion = null;
        if (source.TryGet(root + "mmc-pack.json") is { } pack)
        {
            using var json = source.ReadJson(pack);
            foreach (var component in json.RootElement.GetProperty("components").EnumerateArray())
            {
                string uid = component.GetProperty("uid").GetString() ?? "";
                string? version = component.TryGetProperty("version", out var v) ? v.GetString() : null;
                if (uid == "net.minecraft") minecraft = version;
                else if (LoaderId(uid) is { } id) { loader = id; loaderVersion = version; }
            }
        }
        ApplyLoader(instance, minecraft, loader, loaderVersion);
        instance.Source = "Prism / MultiMC";
        if (source.TryGet(root + "instance.cfg") is { } cfg)
            foreach (string line in source.ReadText(cfg).Split('\n'))
                if (line.StartsWith("name=", StringComparison.Ordinal) && line[5..].Trim() is { Length: > 0 } n) instance.Name = n;
        progress?.Report(new("Copying files…", 0.5));
        string game = source.Entries.Any(e => e.Path.StartsWith(root + ".minecraft/", StringComparison.Ordinal)) ? ".minecraft/" : "minecraft/";
        // An export is the player's own game folder: only mods, settings, packs and worlds are taken from it.
        await CopyTreeAsync(source, root + game, instance.Directory, true, ct);
    }

    // ---------- Anything else: a folder/archive with mods/, or loose .jar files

    private async Task LooseAsync(PackSource source, string root, Instance instance, IProgress<InstallProgress>? progress, CancellationToken ct)
    {
        instance.Source = "Files";
        progress?.Report(new("Copying files…", 0.5));
        // Usually a zipped .minecraft or game folder: only mods, settings, packs and worlds are taken from it.
        if (root != "\0jars") { await CopyTreeAsync(source, root, instance.Directory, true, ct); return; }
        foreach (var entry in source.Entries.Where(e => IsModFile(e.Path)))
            await SaveEntryAsync(entry, SafeFiles.Under(instance.Directory, "mods/" + SafeFiles.FileName(entry.Path)), ct);
    }

    // ---------- Helpers

    // gameFolder: the source is a player's own game folder, so only IsGameContent paths are copied. Credential files are
    // never copied from anywhere.
    private async Task CopyTreeAsync(PackSource source, string prefix, string destination, bool gameFolder, CancellationToken ct)
    {
        foreach (var entry in source.Entries.Where(e => e.Path.StartsWith(prefix, StringComparison.Ordinal)))
        {
            string relative = entry.Path[prefix.Length..];
            if (relative.Length == 0 || SafeFiles.IsCredentialFile(relative) || (gameFolder && !SafeFiles.IsGameContent(relative))) continue;
            await SaveEntryAsync(entry, SafeFiles.Under(destination, relative), ct);
        }
    }

    private async Task SaveEntryAsync(PackEntry entry, string target, CancellationToken ct)
    {
        await using var input = entry.Open();
        await SaveAsync(input, target, SafeFiles.MaxFileBytes, null, null, ct);
    }

    private async Task SaveAsync(Stream input, string target, long limit, string? sha512, string? sha1, CancellationToken ct)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(target)!);
        string part = target + ".part";
        try
        {
            await using (var output = new FileStream(part, FileMode.Create, FileAccess.ReadWrite, FileShare.None))
            {
                long size = await SafeFiles.CopyBoundedAsync(input, output, Math.Min(limit, SafeFiles.MaxPackBytes - Interlocked.Read(ref written)), ct);
                if (Interlocked.Add(ref written, size) > SafeFiles.MaxPackBytes)
                    throw new UserVisibleException("The pack is larger than it claims, or larger than Token Vault allows.");
                if (sha512 is not null || sha1 is not null)
                {
                    output.Position = 0;
                    byte[] hash = sha512 is not null ? await SHA512.HashDataAsync(output, ct) : await SHA1.HashDataAsync(output, ct);
                    if (!Convert.ToHexString(hash).Equals(sha512 ?? sha1, StringComparison.OrdinalIgnoreCase))
                        throw new UserVisibleException("A downloaded mod didn't match its published checksum, so it wasn't installed.");
                }
            }
            File.Move(part, target, overwrite: true);
        }
        finally { File.Delete(part); }
    }

    private async Task DownloadAsync(Uri url, string target, long limit, string? sha512, string? sha1, CancellationToken ct)
    {
        var (stream, _) = await OpenFollowingAsync(url, ct);
        await using (stream) await SaveAsync(stream, target, limit, sha512, sha1, ct);
    }

    // Follows up to five HTTPS redirects, only to known mod-hosting sites.
    private async Task<(Stream Body, Uri Final)> OpenFollowingAsync(Uri url, CancellationToken ct)
    {
        for (int hop = 0; hop < 6; hop++)
        {
            if (url.Scheme != "https" || url.UserInfo.Length > 0 || !url.IsDefaultPort)
                throw new UserVisibleException("Refusing a non-HTTPS download: " + url.Host);
            var response = await http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, ct);
            if ((int)response.StatusCode is >= 300 and < 400 && response.Headers.Location is { } location)
            {
                response.Dispose();
                var next = location.IsAbsoluteUri ? location : new Uri(url, location);
                if (!RedirectSuffixes.Any(s => ("." + next.Host).EndsWith(s, StringComparison.OrdinalIgnoreCase)))
                    throw new UserVisibleException("A download redirected to an unexpected site: " + next.Host);
                url = next;
                continue;
            }
            if (!response.IsSuccessStatusCode)
            {
                int code = (int)response.StatusCode;
                response.Dispose();
                throw new UserVisibleException($"Download failed ({code}) from {url.Host}.");
            }
            return (new ResponseStream(response, await response.Content.ReadAsStreamAsync(ct)), url);
        }
        throw new UserVisibleException("Too many redirects.");
    }

    private static async Task ForEachAsync<T>(IEnumerable<T> items, int parallel, Func<T, Task> body, CancellationToken ct)
    {
        using var gate = new SemaphoreSlim(parallel);
        await Task.WhenAll(items.Select(async item =>
        {
            await gate.WaitAsync(ct);
            try { await body(item); } finally { gate.Release(); }
        }));
    }

    private sealed class ResponseStream(HttpResponseMessage response, Stream inner) : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count) => inner.Read(buffer, offset, count);
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default) => inner.ReadAsync(buffer, ct);
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        protected override void Dispose(bool disposing) { if (disposing) { inner.Dispose(); response.Dispose(); } base.Dispose(disposing); }
    }
}

internal sealed record PackEntry(string Path, long Size, Func<Stream> Open);

// A pack as a flat list of files with '/'-separated relative paths. Links and directories are not listed.
internal sealed class PackSource : IDisposable
{
    private readonly IDisposable? owner;
    public IReadOnlyList<PackEntry> Entries { get; }
    private PackSource(IReadOnlyList<PackEntry> entries, IDisposable? owner) { Entries = entries; this.owner = owner; }

    public static PackSource Open(string path)
    {
        if (Directory.Exists(path))
        {
            string root = Path.GetFullPath(path);
            var options = new EnumerationOptions { RecurseSubdirectories = true, AttributesToSkip = FileAttributes.ReparsePoint | FileAttributes.System, IgnoreInaccessible = true };
            var files = Directory.EnumerateFiles(root, "*", options).Take(SafeFiles.MaxEntries + 1)
                .Select(f => new PackEntry(Path.GetRelativePath(root, f).Replace('\\', '/'), new FileInfo(f).Length, () => File.OpenRead(f))).ToList();
            return Checked(files, null);
        }
        if (PackImporter.IsModFile(path))
            return new PackSource([new PackEntry(Path.GetFileName(path), new FileInfo(path).Length, () => File.OpenRead(path))], null);
        IArchive archive;
        try { archive = ArchiveFactory.Open(path); }
        catch (Exception ex) when (ex is InvalidOperationException or InvalidDataException or IOException or NotSupportedException or ArgumentException)
        { throw new UserVisibleException("This file isn't a modpack or archive Token Vault can read."); }
        try
        {
            var entries = archive.Entries.Where(e => !e.IsDirectory && e.Key is not null && e.LinkTarget is null).Take(SafeFiles.MaxEntries + 1)
                .Select(e => new PackEntry(e.Key!.Replace('\\', '/').TrimStart('/'), e.Size, () => e.OpenEntryStream())).ToList();
            return Checked(entries, archive);
        }
        catch { archive.Dispose(); throw; }
    }

    private static PackSource Checked(List<PackEntry> entries, IDisposable? owner)
    {
        if (entries.Count > SafeFiles.MaxEntries || entries.Sum(e => Math.Max(0, e.Size)) > SafeFiles.MaxPackBytes)
        {
            owner?.Dispose();
            throw new UserVisibleException("This pack is too large to import.");
        }
        return new PackSource(entries, owner);
    }

    public PackEntry Get(string path) => TryGet(path) ?? throw new UserVisibleException("The pack is missing " + path + ".");
    public PackEntry? TryGet(string path) => Entries.FirstOrDefault(e => e.Path == path);

    public JsonDocument ReadJson(PackEntry entry)
    {
        try { return JsonDocument.Parse(ReadBytes(entry, 32 * 1024 * 1024)); }
        catch (JsonException) { throw new UserVisibleException("The pack's " + Path.GetFileName(entry.Path) + " is not valid JSON."); }
    }

    public string ReadText(PackEntry entry) => System.Text.Encoding.UTF8.GetString(ReadBytes(entry, 1024 * 1024));

    private static byte[] ReadBytes(PackEntry entry, long limit)
    {
        using var input = entry.Open();
        using var buffer = new MemoryStream();
        SafeFiles.CopyBoundedAsync(input, buffer, limit, CancellationToken.None).GetAwaiter().GetResult();
        return buffer.ToArray();
    }

    public void Dispose() => owner?.Dispose();
}
