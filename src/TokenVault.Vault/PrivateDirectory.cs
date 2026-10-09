using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using TokenVault.Core;

namespace TokenVault.Vault;

// The data folder (config, DPAPI refresh-token blob, audit log) is readable only by this Windows user and SYSTEM.
// Inheritance is cut so no sandbox/AppContainer grant from a parent folder can ever reach it.
[SupportedOSPlatform("windows")]
public static class PrivateDirectory
{
    public static void Ensure(string path)
    {
        var info = Directory.CreateDirectory(path);
        if ((info.Attributes & FileAttributes.ReparsePoint) != 0)
            throw new UserVisibleException("The Token Vault data folder must not be a link or junction: " + path);
        var user = WindowsIdentity.GetCurrent().User!;
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var acl = new DirectorySecurity();
        acl.SetOwner(user);
        acl.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        foreach (var sid in new[] { user, system })
            acl.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        info.SetAccessControl(acl);
        foreach (FileSystemAccessRule rule in info.GetAccessControl().GetAccessRules(true, true, typeof(SecurityIdentifier)))
            if (rule.AccessControlType == AccessControlType.Allow && rule.IdentityReference != user && rule.IdentityReference != system)
                throw new UserVisibleException("The Token Vault data folder has unexpected permissions; refusing to store sign-in data.");
    }
}
