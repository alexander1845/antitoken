using System.IO.Compression;
using System.Net;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace TokenVault.Vault;

// Values fixed at build time (Directory.Build.props, or -p: on the publish command line). Nothing here is a secret:
// the update key is a PUBLIC key and a PostHog project key is meant to ship inside clients.
public static class BuildInfo
{
    private static string Meta(string key) =>
        typeof(BuildInfo).Assembly.GetCustomAttributes<AssemblyMetadataAttribute>().FirstOrDefault(a => a.Key == key)?.Value ?? "";

    public static Version Version => Updater.Normalize(typeof(BuildInfo).Assembly.GetName().Version ?? new Version(0, 0, 0));
    public static string UpdateRepository => Meta("TokenVault.UpdateRepository");
    public static string UpdatePublicKey => Meta("TokenVault.UpdatePublicKey");
    public static string PostHogProjectKey => Meta("TokenVault.PostHogProjectKey");
    public static string PostHogHost => Meta("TokenVault.PostHogHost");
}

public sealed class UpdateException(string message) : Exception(message);

public sealed record UpdateInfo(Version Version, Uri Page, Uri? Package, Uri? Manifest, Uri? Signature)
{
    public bool Installable => Package is not null && Manifest is not null && Signature is not null;
}

public sealed record UpdateManifest(Version Version, string File, string Sha256, long Size);

public sealed record StagedUpdate(Version Version, string Executable, string? Probe);

// Checks GitHub Releases for a newer Token Vault and installs it.
//
// Trust: a release is installed only if its manifest (version, file name, SHA-256, size) carries a valid ECDSA P-256
// signature from the key whose PUBLIC half is built into this program. The private key lives only in the release
// pipeline's secrets, so neither GitHub, a network attacker nor someone who can upload release files can push code
// to players without it. The manifest's version must be newer than this build, so an old signed release can't be
// replayed to roll players back. A build without a public key only tells the player that a release exists.
public sealed class Updater(HttpClient http, string repository, string publicKey, Version current)
{
    public const string PackageName = "TokenVault-win-x64.zip";
    public const string ManifestName = "TokenVault-update.json";
    public const string SignatureName = ManifestName + ".sig";
    private const long MaxPackage = 512L * 1024 * 1024, MaxExecutable = 400L * 1024 * 1024;

    private static readonly string[] GitHubHosts = ["api.github.com", "github.com"];
    private static readonly string[] DownloadSuffixes = [".githubusercontent.com"];

    public bool CanInstall => publicKey.Length > 0;

    public static HttpClient CreateHttp()
    {
        var client = new HttpClient(new SocketsHttpHandler
        {
            AllowAutoRedirect = false, UseCookies = false, AutomaticDecompression = DecompressionMethods.All,
            ConnectTimeout = TimeSpan.FromSeconds(20)
        }) { Timeout = TimeSpan.FromMinutes(15) };
        client.DefaultRequestHeaders.UserAgent.ParseAdd("TokenVault-Updater/" + BuildInfo.Version);
        return client;
    }

    public static Version Normalize(Version v) => new(v.Major, v.Minor, Math.Max(0, v.Build));

    public static Version? ParseTag(string? tag) =>
        tag is not null && Regex.Match(tag, @"^v?(\d{1,5})\.(\d{1,5})\.(\d{1,5})$") is { Success: true } m
            ? new Version(int.Parse(m.Groups[1].Value), int.Parse(m.Groups[2].Value), int.Parse(m.Groups[3].Value))
            : null;

    // The newest published release if it is newer than this build, else null.
    public async Task<UpdateInfo?> CheckAsync(CancellationToken ct)
    {
        if (!Regex.IsMatch(repository, @"^[A-Za-z0-9-]{1,39}/[A-Za-z0-9._-]{1,100}$")) return null;
        byte[] body = await GetAsync(new Uri($"https://api.github.com/repos/{repository}/releases/latest"), 1024 * 1024, ct);
        using var json = JsonDocument.Parse(body);
        var root = json.RootElement;
        if (root.TryGetProperty("draft", out var draft) && draft.ValueKind == JsonValueKind.True) return null;
        if (root.TryGetProperty("prerelease", out var pre) && pre.ValueKind == JsonValueKind.True) return null;
        if (ParseTag(root.GetProperty("tag_name").GetString()) is not { } version || version <= Normalize(current)) return null;
        var page = new Uri(root.GetProperty("html_url").GetString()!);
        if (page.Scheme != "https" || page.Host != "github.com") return null;
        Uri? Asset(string name)
        {
            if (!root.TryGetProperty("assets", out var assets)) return null;
            foreach (var asset in assets.EnumerateArray())
                if (asset.GetProperty("name").GetString() == name &&
                    Uri.TryCreate(asset.GetProperty("browser_download_url").GetString(), UriKind.Absolute, out var url) &&
                    url.Scheme == "https" && url.Host == "github.com")
                    return url;
            return null;
        }
        return new UpdateInfo(version, page, Asset(PackageName), Asset(ManifestName), Asset(SignatureName));
    }

    // Downloads the release, checks it against its signed manifest and unpacks TokenVault.exe (and AuthlibProbe.java)
    // into staging. Nothing outside staging is touched; Install puts the files in place.
    public async Task<StagedUpdate> DownloadAsync(UpdateInfo info, string staging, CancellationToken ct)
    {
        if (!CanInstall) throw new UpdateException("This build can't verify updates.");
        if (!info.Installable) throw new UpdateException("The release has no signed update package.");
        byte[] manifestBytes = await GetAsync(info.Manifest!, 64 * 1024, ct);
        byte[] signature = await GetAsync(info.Signature!, 8 * 1024, ct);
        var manifest = VerifyManifest(manifestBytes, System.Text.Encoding.ASCII.GetString(signature), publicKey);
        if (manifest.Version != info.Version || manifest.Version <= Normalize(current))
            throw new UpdateException("The signed manifest is for a different version.");

        Directory.CreateDirectory(staging);
        foreach (string stale in Directory.EnumerateFiles(staging)) File.Delete(stale);
        string package = Path.Combine(staging, PackageName);
        using (var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256))
        {
            await using (var output = new FileStream(package, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            await using (var body = await OpenAsync(info.Package!, ct))
            {
                byte[] buffer = new byte[81920];
                long total = 0;
                int read;
                while ((read = await body.ReadAsync(buffer, ct)) > 0)
                {
                    total += read;
                    if (total > manifest.Size || total > MaxPackage) throw new UpdateException("The download is larger than its signed size.");
                    sha.AppendData(buffer, 0, read);
                    await output.WriteAsync(buffer.AsMemory(0, read), ct);
                }
                if (total != manifest.Size) throw new UpdateException("The download is smaller than its signed size.");
            }
            if (!CryptographicOperations.FixedTimeEquals(sha.GetHashAndReset(), Convert.FromHexString(manifest.Sha256)))
                throw new UpdateException("The download doesn't match its signed checksum.");
        }

        string? exe = null, probe = null;
        using (var zip = ZipFile.OpenRead(package))
            foreach (var entry in zip.Entries)
            {
                string target;
                if (entry.Name.Equals("TokenVault.exe", StringComparison.OrdinalIgnoreCase) && exe is null) target = exe = Path.Combine(staging, "TokenVault.exe.new");
                else if (entry.Name.Equals("AuthlibProbe.java", StringComparison.Ordinal) && probe is null) target = probe = Path.Combine(staging, "AuthlibProbe.java");
                else continue;
                await using var input = entry.Open();
                await using var output = new FileStream(target, FileMode.CreateNew, FileAccess.Write, FileShare.None);
                long copied = 0;
                byte[] buffer = new byte[81920];
                int read;
                while ((read = await input.ReadAsync(buffer, ct)) > 0)
                {
                    if ((copied += read) > MaxExecutable) throw new UpdateException("The update package is malformed.");
                    await output.WriteAsync(buffer.AsMemory(0, read), ct);
                }
            }
        File.Delete(package);
        return new StagedUpdate(manifest.Version, exe ?? throw new UpdateException("The update package has no TokenVault.exe."), probe);
    }

    // Manifest: {"product":"TokenVault","version":"1.2.3","file":"TokenVault-win-x64.zip","sha256":"<hex>","size":123}
    // Signature: base64 of an ASN.1 DER ECDSA P-256 signature over the manifest bytes exactly as published (openssl dgst -sha256 -sign).
    public static UpdateManifest VerifyManifest(byte[] manifest, string signatureBase64, string publicKeyBase64)
    {
        try
        {
            using var key = ECDsa.Create();
            key.ImportSubjectPublicKeyInfo(Convert.FromBase64String(publicKeyBase64), out _);
            if (key.KeySize != 256) throw new UpdateException("The built-in update key is not a P-256 key.");
            if (!key.VerifyData(manifest, Convert.FromBase64String(signatureBase64.Trim()), HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence))
                throw new UpdateException("The update's signature is not valid.");
        }
        catch (FormatException) { throw new UpdateException("The update's signature is malformed."); }
        catch (CryptographicException) { throw new UpdateException("The update's signature is malformed."); }
        try
        {
            using var json = JsonDocument.Parse(manifest);
            var r = json.RootElement;
            if (r.GetProperty("product").GetString() != "TokenVault" || r.GetProperty("file").GetString() != PackageName)
                throw new UpdateException("The signed manifest is for something else.");
            var version = ParseTag(r.GetProperty("version").GetString()) ?? throw new UpdateException("The signed manifest has no version.");
            string sha = r.GetProperty("sha256").GetString() ?? "";
            if (!Regex.IsMatch(sha, "^[0-9a-fA-F]{64}$")) throw new UpdateException("The signed manifest has no checksum.");
            long size = r.GetProperty("size").GetInt64();
            if (size is <= 0 or > MaxPackage) throw new UpdateException("The signed manifest has an invalid size.");
            return new UpdateManifest(version, PackageName, sha, size);
        }
        catch (Exception ex) when (ex is JsonException or KeyNotFoundException or InvalidOperationException or FormatException)
        { throw new UpdateException("The signed manifest is malformed."); }
    }

    // Puts the staged program in place of the running one. Windows lets a running .exe be renamed but not overwritten,
    // so the current file becomes "TokenVault.exe.old" (removed on the next start) and the new one takes its name.
    public static void Install(StagedUpdate update, string executable)
    {
        string directory = Path.GetDirectoryName(executable)!;
        string old = executable + ".old";
        try { File.Delete(old); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { old = executable + "." + Guid.NewGuid().ToString("N")[..8] + ".old"; }
        File.Move(executable, old);
        try { File.Move(update.Executable, executable); }
        catch { File.Move(old, executable); throw; }
        if (update.Probe is not null)
            try { File.Copy(update.Probe, Path.Combine(directory, "AuthlibProbe.java"), overwrite: true); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { } // optional file
    }

    // Removes what an earlier update left behind. Files still in use are left for next time.
    public static void CleanUp(string executable)
    {
        string directory = Path.GetDirectoryName(executable)!, name = Path.GetFileName(executable);
        foreach (string file in Directory.EnumerateFiles(directory, name + ".*old"))
            try { File.Delete(file); } catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }

    private async Task<byte[]> GetAsync(Uri url, int limit, CancellationToken ct)
    {
        await using var body = await OpenAsync(url, ct);
        using var buffer = new MemoryStream();
        byte[] chunk = new byte[16384];
        int read;
        while ((read = await body.ReadAsync(chunk, ct)) > 0)
        {
            if (buffer.Length + read > limit) throw new UpdateException("An update file is larger than expected.");
            buffer.Write(chunk, 0, read);
        }
        return buffer.ToArray();
    }

    // HTTPS only, GitHub only (release downloads redirect to GitHub's download host).
    private async Task<Stream> OpenAsync(Uri url, CancellationToken ct)
    {
        for (int hop = 0; hop < 5; hop++)
        {
            bool allowed = url.Scheme == "https" && url.IsDefaultPort && url.UserInfo.Length == 0 &&
                (GitHubHosts.Contains(url.Host) || DownloadSuffixes.Any(s => url.Host.EndsWith(s, StringComparison.OrdinalIgnoreCase)));
            if (!allowed) throw new UpdateException("An update download pointed outside GitHub.");
            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            if (url.Host == "api.github.com") request.Headers.Accept.ParseAdd("application/vnd.github+json");
            var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
            if ((int)response.StatusCode is >= 300 and < 400 && response.Headers.Location is { } location)
            {
                response.Dispose();
                url = location.IsAbsoluteUri ? location : new Uri(url, location);
                continue;
            }
            if (!response.IsSuccessStatusCode)
            {
                int code = (int)response.StatusCode;
                response.Dispose();
                throw new UpdateException($"GitHub answered {code}.");
            }
            return new OwningStream(response, await response.Content.ReadAsStreamAsync(ct));
        }
        throw new UpdateException("Too many redirects.");
    }

    private sealed class OwningStream(HttpResponseMessage response, Stream inner) : Stream
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
