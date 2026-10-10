using System.Text.RegularExpressions;
using TokenVault.Core;

namespace TokenVault.Packs;

public static class SafeFiles
{
    public const long MaxFileBytes = 2L * 1024 * 1024 * 1024;
    public const long MaxPackBytes = 16L * 1024 * 1024 * 1024;
    public const int MaxEntries = 100_000;

    // Sign-in files that launchers and clients keep next to game data (official launcher, Prism/MultiMC, TLauncher,
    // Essential, Lunar, Feather, Meteor, Wurst and others). If someone zips up their whole .minecraft or launcher folder,
    // these must not be copied into a folder the sandbox can read. Names are matched exactly, and any file whose name
    // mentions accounts, tokens, credentials, passwords or alts is skipped as well: a skipped config file costs a
    // setting, a copied one can cost the account.
    private static readonly HashSet<string> CredentialFiles = new(StringComparer.OrdinalIgnoreCase)
    {
        "accounts.json", "launcher_accounts.json", "launcher_accounts_microsoft_store.json",
        "launcher_msa_credentials.bin", "launcher_msa_credentials_microsoft_store.bin",
        "launcher_profiles.json", "launcher_profiles_microsoft_store.json", "launcher_ui_state.json",
        "msa_credentials.bin", "tokens.json", "vault.bin", "tlauncherprofiles.json", "tlauncher_profiles.json",
        "microsoft_accounts.json", "accounts.nbt", "alts.json", "alts.encrypted_json", "alts.txt"
    };
    private static readonly string[] CredentialWords = ["account", "token", "credential", "password", "passwd", "secret", "msa_", "alts."];

    public static bool IsCredentialFile(string relative)
    {
        string name = Path.GetFileName(relative.Replace('\\', '/'));
        return CredentialFiles.Contains(name) || CredentialWords.Any(w => name.Contains(w, StringComparison.OrdinalIgnoreCase));
    }

    // What is taken from a player's own game folder (a zipped .minecraft, a Prism/MultiMC export): mods and their
    // settings, packs and worlds. Everything else there (other launchers' data, caches, logs, versions, libraries) is left out.
    private static readonly HashSet<string> GameFolders = new(StringComparer.OrdinalIgnoreCase)
    {
        "mods", "config", "defaultconfigs", "kubejs", "scripts", "resourcepacks", "shaderpacks", "datapacks", "saves",
        "schematics", "global_packs", "openloader"
    };
    private static readonly HashSet<string> GameFiles = new(StringComparer.OrdinalIgnoreCase)
    {
        "options.txt", "optionsof.txt", "optionsshaders.txt"
    };

    public static bool IsGameContent(string relative)
    {
        string[] parts = relative.Replace('\\', '/').Split('/', StringSplitOptions.RemoveEmptyEntries);
        return parts.Length == 1 ? GameFiles.Contains(parts[0]) : parts.Length > 1 && GameFolders.Contains(parts[0]);
    }

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
