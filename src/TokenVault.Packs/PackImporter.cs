using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using SharpCompress.Archives;
using TokenVault.Core;
using TokenVault.Launcher;

namespace TokenVault.Packs;

// Imports modpacks into a NEW instance folder. Supported:
//   Modrinth .mrpack · CurseForge .zip (manifest.json) · Prism/MultiMC exports (mmc-pack.json / instance.cfg)
//   any .zip / .7z / .rar / .tar(.gz) or folder containing mods or a .minecraft-style folder · single .jar mods.
// Everything is unpacked by Token Vault into a folder the sandbox has never had access to, then handed to the
// sandbox at launch. Downloads are HTTPS-only, from the hosts each format allows, and hash-checked when the
// pack provides hashes. Mods still only ever run inside the sandbox.
public sealed class PackImporter(HttpClient http)
{
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

    internal static void RequireCompatible(string? minecraft, string? loader, string? otherLoader)
    {
        string supported = new Configuration().MinecraftVersion;
        if (otherLoader is not null)
            throw new UserVisibleException($"This pack uses {otherLoader}. Token Vault runs Fabric mods only, so it can't play this pack.");
        if (minecraft is not null && minecraft != supported)
            throw new UserVisibleException($"This pack is made for Minecraft {minecraft}. Token Vault currently plays Minecraft {supported} only.");
        _ = loader;
    }

    private static string? OtherLoader(string id) => id.ToLowerInvariant() switch
    {
        var s when s.StartsWith("neoforge") || s.StartsWith("net.neoforged") => "NeoForge",
        var s when s.StartsWith("forge") || s.StartsWith("net.minecraftforge") => "Forge",
        var s when s.StartsWith("quilt") || s.StartsWith("org.quiltmc") => "Quilt",
        _ => null
    };

    // ---------- Modrinth (.mrpack)

    private async Task ModrinthAsync(PackSource source, string root, Instance instance, IProgress<InstallProgress>? progress, CancellationToken ct)
    {
        using var index = source.ReadJson(source.Get(root + "modrinth.index.json"));
        var r = index.RootElement;
        if (r.TryGetProperty("game", out var game) && game.GetString() != "minecraft") throw new UserVisibleException("This Modrinth pack is not for Minecraft.");
        var deps = r.GetProperty("dependencies");
        string? minecraft = null, fabric = null, other = null;
        foreach (var dep in deps.EnumerateObject())
        {
            if (dep.Name == "minecraft") minecraft = dep.Value.GetString();
            else if (dep.Name == "fabric-loader") fabric = dep.Value.GetString();
            else other ??= OtherLoader(dep.Name) ?? null;
        }
        RequireCompatible(minecraft, fabric, other);
        instance.Source = "Modrinth";
        instance.LoaderVersion = fabric;
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
        await CopyTreeAsync(source, root + "overrides/", instance.Directory, ct);
        await CopyTreeAsync(source, root + "client-overrides/", instance.Directory, ct);
    }

    // ---------- CurseForge (.zip with manifest.json)

    private async Task CurseForgeAsync(PackSource source, string root, Instance instance, IProgress<InstallProgress>? progress, CancellationToken ct)
    {
        using var manifest = source.ReadJson(source.Get(root + "manifest.json"));
        var r = manifest.RootElement;
        var mc = r.GetProperty("minecraft");
        string? fabric = null, other = null;
        foreach (var loader in mc.GetProperty("modLoaders").EnumerateArray())
        {
            string id = loader.GetProperty("id").GetString() ?? "";
            if (id.StartsWith("fabric-", StringComparison.OrdinalIgnoreCase)) fabric = id["fabric-".Length..];
            else other ??= OtherLoader(id) ?? "an unsupported mod loader";
        }
        RequireCompatible(mc.GetProperty("version").GetString(), fabric, other);
        instance.Source = "CurseForge";
        instance.LoaderVersion = fabric;
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
        await CopyTreeAsync(source, root + overrides, instance.Directory, ct);
    }

    // ---------- Prism Launcher / MultiMC export

    private static async Task PrismAsync(PackSource source, string root, Instance instance, IProgress<InstallProgress>? progress, CancellationToken ct)
    {
        string? minecraft = null, fabric = null, other = null;
        if (source.TryGet(root + "mmc-pack.json") is { } pack)
        {
            using var json = source.ReadJson(pack);
            foreach (var component in json.RootElement.GetProperty("components").EnumerateArray())
            {
                string uid = component.GetProperty("uid").GetString() ?? "";
                string? version = component.TryGetProperty("version", out var v) ? v.GetString() : null;
                if (uid == "net.minecraft") minecraft = version;
                else if (uid == "net.fabricmc.fabric-loader") fabric = version;
                else other ??= OtherLoader(uid);
            }
        }
        RequireCompatible(minecraft, fabric, other);
        instance.Source = "Prism / MultiMC";
        instance.LoaderVersion = fabric;
        if (source.TryGet(root + "instance.cfg") is { } cfg)
            foreach (string line in source.ReadText(cfg).Split('\n'))
                if (line.StartsWith("name=", StringComparison.Ordinal) && line[5..].Trim() is { Length: > 0 } n) instance.Name = n;
        progress?.Report(new("Copying files…", 0.5));
        string game = source.Entries.Any(e => e.Path.StartsWith(root + ".minecraft/", StringComparison.Ordinal)) ? ".minecraft/" : "minecraft/";
        await CopyTreeAsync(source, root + game, instance.Directory, ct);
    }

    // ---------- Anything else: a folder/archive with mods/, or loose .jar files

    private static async Task LooseAsync(PackSource source, string root, Instance instance, IProgress<InstallProgress>? progress, CancellationToken ct)
    {
        instance.Source = "Files";
        progress?.Report(new("Copying files…", 0.5));
        if (root != "\0jars") { await CopyTreeAsync(source, root, instance.Directory, ct); return; }
        foreach (var entry in source.Entries.Where(e => IsModFile(e.Path)))
            await SaveEntryAsync(entry, SafeFiles.Under(instance.Directory, "mods/" + SafeFiles.FileName(entry.Path)), ct);
    }

    // ---------- Helpers

    private static async Task CopyTreeAsync(PackSource source, string prefix, string destination, CancellationToken ct)
    {
        foreach (var entry in source.Entries.Where(e => e.Path.StartsWith(prefix, StringComparison.Ordinal)))
        {
            string relative = entry.Path[prefix.Length..];
            if (relative.Length == 0 || SafeFiles.IsCredentialFile(relative)) continue;
            await SaveEntryAsync(entry, SafeFiles.Under(destination, relative), ct);
        }
    }

    private static async Task SaveEntryAsync(PackEntry entry, string target, CancellationToken ct)
    {
        await using var input = entry.Open();
        await SaveAsync(input, target, SafeFiles.MaxFileBytes, null, null, ct);
    }

    private static async Task SaveAsync(Stream input, string target, long limit, string? sha512, string? sha1, CancellationToken ct)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(target)!);
        string part = target + ".part";
        try
        {
            await using (var output = new FileStream(part, FileMode.Create, FileAccess.ReadWrite, FileShare.None))
            {
                await SafeFiles.CopyBoundedAsync(input, output, limit, ct);
                if (sha512 is not null || sha1 is not null)
                {
                    output.Position = 0;
                    byte[] hash = sha512 is not null ? await SHA512.HashDataAsync(output, ct) : await SHA1.HashDataAsync(output, ct);
                    if (!Convert.ToHexString(hash).Equals(sha512 ?? sha1, StringComparison.OrdinalIgnoreCase))
                        throw new UserVisibleException("A downloaded mod didn't match the checksum in the pack. The import was stopped.");
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
