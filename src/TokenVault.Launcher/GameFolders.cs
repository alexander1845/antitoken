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
        var user = WindowsIdentity.GetCurrent().User!;
        var info = new DirectoryInfo(root);
        if (!info.Exists)
        {
            info.Create();
            var acl = new DirectorySecurity();
            acl.SetOwner(user);
            acl.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            foreach (var sid in new[] { user, System, Administrators })
                acl.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
            info.SetAccessControl(acl);
            // Low integrity label, inherited by everything inside. The sandbox runs at low integrity and Windows blocks it
            // from writing medium-integrity files even where folder permissions allow it. The label grants nothing by
            // itself: the permissions above still keep every other account and sandbox out. Labelling the folder while
            // it is empty means nothing has to be relabelled later; if Windows refuses, the one-time setup does it.
            try { GameSandbox.SetLowIntegrityLabel(root); }
            catch (UserVisibleException ex) { log?.Invoke(ex.Message); }
        }
        Verify(info, user, sandbox);
        foreach (string child in new[] { "Minecraft", "Instances", "Run" }) Directory.CreateDirectory(Path.Combine(root, child));
        MigrateInstances(log);
    }

    private static void Verify(DirectoryInfo info, SecurityIdentifier user, SecurityIdentifier? sandbox)
    {
        if ((info.Attributes & FileAttributes.ReparsePoint) != 0)
            throw new UserVisibleException(info.FullName + " must be a normal folder, not a link.");
        var acl = info.GetAccessControl();
        bool ok = acl.AreAccessRulesProtected && acl.GetOwner(typeof(SecurityIdentifier)) is SecurityIdentifier owner &&
                  (owner == user || owner == Administrators);
        foreach (FileSystemAccessRule rule in acl.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            if (rule.AccessControlType == AccessControlType.Allow && rule.IdentityReference is SecurityIdentifier sid &&
                sid != user && sid != System && sid != Administrators && sid != sandbox)
                ok = false;
        if (!ok)
            throw new UserVisibleException($"{info.FullName} already exists and other accounts on this PC can change it. " +
                "Rename or delete that folder, then try again; Token Vault will recreate it with private permissions.");
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
