using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using TokenVault.Core;

namespace TokenVault.Vault;

[SupportedOSPlatform("windows")]
public static class Isolation
{
    public static void Verify(Configuration config, string configPath)
    {
        string current = WindowsIdentity.GetCurrent().User!.Value;
        if (config.HardeningMode == "same-user-development")
        {
            Console.Error.WriteLine("DEVELOPMENT MODE: same-user malware can read this vault. No process-isolation guarantee.");
            return;
        }
        if (current != config.VaultUserSid || current == config.GameUserSid || !config.GameUserSid.StartsWith("S-1-", StringComparison.Ordinal))
            throw new InvalidOperationException("Run as the configured separate vault account.");
        if (new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator))
            throw new InvalidOperationException("Run the vault without administrator privileges.");
        var trusted = new HashSet<string> { "S-1-5-18", "S-1-5-32-544", current };
        CheckDirectory(AppContext.BaseDirectory, trusted);
        CheckDirectory(Path.GetDirectoryName(Path.GetFullPath(configPath))!, trusted);
        CheckAncestors(AppContext.BaseDirectory, trusted);
        CheckAncestors(Path.GetDirectoryName(Path.GetFullPath(configPath))!, trusted);
        CheckFile(Path.GetFullPath(configPath), trusted);
        foreach (string file in Directory.EnumerateFiles(AppContext.BaseDirectory)) CheckFile(file, trusted);
        string data = Configuration.Expand(config.DataDirectory);
        if (!Directory.Exists(data)) throw new InvalidOperationException("Provision the protected data directory first.");
        CheckDirectory(data, trusted, protectReads: true);
        CheckAncestors(data, trusted);
        foreach (string file in Directory.EnumerateFiles(data)) CheckFile(file, trusted, protectReads: true);
    }

    private static void CheckAncestors(string path, HashSet<string> trusted)
    {
        // Writable ancestors must not permit replacing a protected child directory.
        for (var parent = Directory.GetParent(Path.TrimEndingDirectorySeparator(path)); parent is not null; parent = parent.Parent)
        {
            if ((parent.Attributes & FileAttributes.ReparsePoint) != 0) throw new InvalidOperationException("Protected paths cannot traverse reparse points.");
            var acl = parent.GetAccessControl();
            string? owner = acl.GetOwner(typeof(SecurityIdentifier))?.Value;
            // TrustedInstaller commonly owns Program Files / Windows directories.
            const string trustedInstaller = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
            if (owner is null || (!trusted.Contains(owner) && owner != trustedInstaller)) throw new InvalidOperationException("Untrusted ancestor owner.");
            foreach (FileSystemAccessRule rule in acl.GetAccessRules(true, true, typeof(SecurityIdentifier)))
                if (rule.AccessControlType == AccessControlType.Allow && !trusted.Contains(rule.IdentityReference.Value) &&
                    rule.IdentityReference.Value != trustedInstaller &&
                    (rule.PropagationFlags & PropagationFlags.InheritOnly) == 0 &&
                    (rule.FileSystemRights & (FileSystemRights.DeleteSubdirectoriesAndFiles | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership)) != 0)
                    throw new InvalidOperationException("Unsafe ancestor permissions.");
        }
    }

    private static void CheckDirectory(string path, HashSet<string> trusted, bool protectReads = false)
    {
        var info = new DirectoryInfo(path);
        if ((info.Attributes & FileAttributes.ReparsePoint) != 0) throw new InvalidOperationException("Protected directories cannot be reparse points.");
        Check(info.GetAccessControl(), trusted, protectReads);
    }
    private static void CheckFile(string path, HashSet<string> trusted, bool protectReads = false)
    {
        var info = new FileInfo(path);
        if ((info.Attributes & FileAttributes.ReparsePoint) != 0) throw new InvalidOperationException("Protected files cannot be reparse points.");
        Check(info.GetAccessControl(), trusted, protectReads);
    }
    private static void Check(FileSystemSecurity acl, HashSet<string> trusted, bool protectReads)
    {
        string? owner = acl.GetOwner(typeof(SecurityIdentifier))?.Value;
        if (owner is null || !trusted.Contains(owner)) throw new InvalidOperationException("Untrusted owner of vault material.");
        const FileSystemRights write = FileSystemRights.Write | FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles |
                                      FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership;
        FileSystemRights forbidden = protectReads ? write | FileSystemRights.ReadData : write;
        foreach (FileSystemAccessRule rule in acl.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            if (rule.AccessControlType == AccessControlType.Allow && !trusted.Contains(rule.IdentityReference.Value) &&
                (rule.FileSystemRights & forbidden) != 0)
                throw new InvalidOperationException("Vault files/directories have unsafe Windows permissions.");
    }
}
