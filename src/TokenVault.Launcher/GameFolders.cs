using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using TokenVault.Core;

namespace TokenVault.Launcher;

// Creates the game root (see AppPaths.GameRoot) locked to this Windows user, SYSTEM and Administrators. A folder created
// in the drive root would otherwise inherit "Authenticated Users: Modify", letting other accounts on the PC alter the
// game install. Permissions are only set on a brand-new, empty folder, never re-propagated over existing contents.
[SupportedOSPlatform("windows")]
public static class GameFolders
{
    private static readonly SecurityIdentifier System = new(WellKnownSidType.LocalSystemSid, null);
    private static readonly SecurityIdentifier Administrators = new(WellKnownSidType.BuiltinAdministratorsSid, null);

    public static void Ensure(SecurityIdentifier? sandbox, Action<string>? log = null)
    {
        string root = AppPaths.GameRoot;
        Secure(root, sandbox, log);
        foreach (string child in new[] { "Minecraft", "Instances", "Run" }) Directory.CreateDirectory(Path.Combine(root, child));
        MigrateInstances(log);
    }

    // Creates the folder private to this user, or makes an existing one private (see TryMakePrivate). Throws when it
    // exists and can't be trusted.
    public static void Secure(string root, SecurityIdentifier? sandbox, Action<string>? log = null)
    {
        var user = WindowsIdentity.GetCurrent().User!;
        var info = new DirectoryInfo(root);
        if (!info.Exists)
        {
            info.Create();
            var acl = new DirectorySecurity();
            acl.SetOwner(user);
            acl.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            AddOwnRules(acl, user);
            info.SetAccessControl(acl);
            // Low integrity label, inherited by everything inside. The sandbox runs at low integrity and Windows blocks it
            // from writing medium-integrity files even where folder permissions allow it. The label grants nothing by
            // itself: the permissions above still keep every other account and sandbox out. Labelling the folder while
            // it is empty means nothing has to be relabelled later; if Windows refuses, the one-time setup does it.
            try { GameSandbox.SetLowIntegrityLabel(root); }
            catch (UserVisibleException ex) { log?.Invoke(ex.Message); }
        }
        else if (!IsPrivate(info, user, sandbox) && TryMakePrivate(info, user, sandbox))
        {
            log?.Invoke($"Made {root} private to your Windows account (an earlier version left other accounts able to change it).");
            if (!GameSandbox.IsLowLabeled(root))
                try { GameSandbox.SetLowIntegrityLabel(root); }
                catch (UserVisibleException ex) { log?.Invoke(ex.Message); }
        }
        if ((info.Attributes & FileAttributes.ReparsePoint) != 0)
            throw new UserVisibleException(info.FullName + " must be a normal folder, not a link.");
        if (!IsPrivate(info, user, sandbox))
            throw new UserVisibleException($"{info.FullName} already exists and other accounts on this PC can change it. " +
                "Rename or delete that folder, then try again; Token Vault will recreate it with private permissions.");
    }

    private static void AddOwnRules(DirectorySecurity acl, SecurityIdentifier user)
    {
        foreach (var sid in new[] { user, System, Administrators })
            acl.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
    }

    private static bool IsPrivate(DirectoryInfo info, SecurityIdentifier user, SecurityIdentifier? sandbox)
    {
        info.Refresh();
        if ((info.Attributes & FileAttributes.ReparsePoint) != 0) return false;
        var acl = info.GetAccessControl();
        bool ok = acl.AreAccessRulesProtected && acl.GetOwner(typeof(SecurityIdentifier)) is SecurityIdentifier owner &&
                  (owner == user || owner == Administrators);
        foreach (FileSystemAccessRule rule in acl.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            if (rule.AccessControlType == AccessControlType.Allow && rule.IdentityReference is SecurityIdentifier sid &&
                sid != user && sid != System && sid != Administrators && sid != sandbox)
                ok = false;
        return ok;
    }

    // Earlier builds could leave the folder with the permissions it inherits from the drive root, which let every account
    // on the PC change it. When this user owns the folder and everything in it, and there are no links inside, it is
    // taken back in place: the inherited permissions are dropped and Windows re-applies ours to everything inside, so the
    // player keeps their worlds and downloads. Anything another account created (it could still change it, as its owner)
    // or a link (permissions would be applied wherever it points) means the folder isn't trusted and is left alone.
    private static bool TryMakePrivate(DirectoryInfo info, SecurityIdentifier user, SecurityIdentifier? sandbox)
    {
        try
        {
            if ((info.Attributes & FileAttributes.ReparsePoint) != 0 || !OwnedBy(info, user)) return false;
            var pending = new Stack<DirectoryInfo>([info]);
            while (pending.TryPop(out var dir))
                foreach (var entry in dir.EnumerateFileSystemInfos("*", new EnumerationOptions { AttributesToSkip = 0, IgnoreInaccessible = false }))
                {
                    if ((entry.Attributes & FileAttributes.ReparsePoint) != 0 || !OwnedBy(entry, user)) return false;
                    if (entry is DirectoryInfo child) pending.Push(child);
                }
            var acl = info.GetAccessControl();
            acl.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            foreach (FileSystemAccessRule rule in acl.GetAccessRules(true, false, typeof(SecurityIdentifier)))
                if (rule.IdentityReference is SecurityIdentifier sid && sid != user && sid != System && sid != Administrators && sid != sandbox)
                    acl.RemoveAccessRuleSpecific(rule);
            AddOwnRules(acl, user);
            info.SetAccessControl(acl);
            return true;
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or PrivilegeNotHeldException) { return false; }
    }

    private static bool OwnedBy(FileSystemInfo entry, SecurityIdentifier user)
    {
        FileSystemSecurity acl = entry is DirectoryInfo dir ? dir.GetAccessControl(AccessControlSections.Owner)
            : ((FileInfo)entry).GetAccessControl(AccessControlSections.Owner);
        return acl.GetOwner(typeof(SecurityIdentifier)) is SecurityIdentifier owner && (owner == user || owner == Administrators || owner == System);
    }

    // Earlier builds kept instances in the user profile, where the sandboxed game can't resolve paths. Moving a folder
    // on the same drive is a rename: nothing inside it is opened or followed.
    private static void MigrateInstances(Action<string>? log)
    {
        if (!Directory.Exists(AppPaths.LegacyInstanceRoot)) return;
        foreach (string old in Directory.EnumerateDirectories(AppPaths.LegacyInstanceRoot))
        {
            string name = Path.GetFileName(old);
            string target = Path.Combine(AppPaths.InstanceRoot, name);
            if (!Guid.TryParseExact(name, "N", out _) || Directory.Exists(target)) continue;
            try { Directory.Move(old, target); log?.Invoke("Moved instance " + name + " to " + AppPaths.InstanceRoot); }
            catch (IOException) { log?.Invoke("Couldn't move instance folder " + old + "; move it into " + AppPaths.InstanceRoot + " by hand."); }
        }
        try { Directory.Delete(AppPaths.LegacyInstanceRoot); } catch (IOException) { }
        string legacyRun = Path.Combine(AppPaths.Root, "Run");
        try { if (Directory.Exists(legacyRun)) Directory.Delete(legacyRun, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }
}
