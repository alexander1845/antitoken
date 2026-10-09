using System.Text.RegularExpressions;
using TokenVault.Core;

namespace TokenVault.Packs;

public static class SafeFiles
{
    public const long MaxFileBytes = 2L * 1024 * 1024 * 1024;
    public const long MaxPackBytes = 16L * 1024 * 1024 * 1024;
    public const int MaxEntries = 100_000;

    // Sign-in files other launchers keep next to game data. If someone zips up their whole .minecraft or launcher
    // folder, these must not be copied into a folder the sandbox can read.
    private static readonly HashSet<string> CredentialFiles = new(StringComparer.OrdinalIgnoreCase)
    {
        "accounts.json", "launcher_accounts.json", "launcher_accounts_microsoft_store.json",
        "launcher_msa_credentials.bin", "launcher_msa_credentials_microsoft_store.bin",
        "launcher_profiles.json", "launcher_profiles_microsoft_store.json", "launcher_ui_state.json",
        "msa_credentials.bin", "tokens.json", "vault.bin"
    };

    public static bool IsCredentialFile(string relative) => CredentialFiles.Contains(Path.GetFileName(relative.Replace('\\', '/')));

    // Resolves a pack-supplied relative path inside root, refusing traversal, device names and links.
    public static string Under(string root, string relative)
    {
        string[] parts = relative.Replace('\\', '/').Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length == 0 || relative.StartsWith('/') || relative.StartsWith('\\') || parts.Any(p => p is "." or ".." || p.EndsWith(' ') || p.EndsWith('.') ||
            p.Any(c => c < 32 || "<>:\"|?*".Contains(c)) ||
            Regex.IsMatch(p, @"^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)))
            throw new UserVisibleException("The pack contains an unsafe file name: " + relative);
        string target = Path.GetFullPath(Path.Combine([root, .. parts]));
        if (!target.StartsWith(Path.TrimEndingDirectorySeparator(Path.GetFullPath(root)) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            throw new UserVisibleException("A pack file would land outside its instance folder.");
        NoLinks(root, target);
        return target;
    }

    // Refuses to write through a link or junction anywhere between root and target.
    public static void NoLinks(string root, string target)
    {
        string stop = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root));
        for (string? path = Path.GetFullPath(target); path is not null; path = Path.GetDirectoryName(path))
        {
            if ((File.Exists(path) || Directory.Exists(path)) && (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
                throw new UserVisibleException("Linked files or folders can't be used here: " + path);
            if (string.Equals(Path.TrimEndingDirectorySeparator(path), stop, StringComparison.OrdinalIgnoreCase)) break;
        }
    }

    public static async Task<long> CopyBoundedAsync(Stream source, Stream target, long limit, CancellationToken ct)
    {
        byte[] buffer = new byte[81920];
        long total = 0;
        int read;
        while ((read = await source.ReadAsync(buffer, ct)) > 0)
        {
            total += read;
            if (total > limit) throw new UserVisibleException("The pack is larger than it claims, or larger than Token Vault allows.");
            await target.WriteAsync(buffer.AsMemory(0, read), ct);
        }
        return total;
    }

    public static string FileName(string name)
    {
        name = Path.GetFileName(name.Replace('\\', '/'));
        foreach (char c in Path.GetInvalidFileNameChars().Concat("<>:\"|?*")) name = name.Replace(c, '_');
        name = name.Trim().TrimEnd('.');
        return name.Length is > 0 and <= 200 ? name : "file";
    }
}
