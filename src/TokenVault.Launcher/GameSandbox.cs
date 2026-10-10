using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
using TokenVault.Core;

namespace TokenVault.Launcher;

// Runs the game JVM (and therefore every Fabric mod) inside a Windows AppContainer: the same OS sandbox used
// for Edge/UWP content. It needs no second Windows account. The container token runs at Low integrity with
// its own SID, so by default it cannot:
//   * read or write files that are not explicitly granted to that SID (browser cookies, the official
//     launcher's sign-in files, Token Vault's DPAPI blob, documents, ...),
//   * open the Token Vault process (or any normal process) to read its memory or inject code,
//   * write outside the folders we grant, send window messages to normal-integrity windows, or reach
//     loopback services, unless a one-time loopback exemption is added for this container only.
// Microsoft services AppContainer escapes as security-boundary vulnerabilities.
[SupportedOSPlatform("windows")]
public sealed class GameSandbox
{
    public const string ProfileName = "TokenVault.MinecraftSandbox";
    private static readonly SecurityIdentifier AllApplicationPackages = new("S-1-15-2-1");
    private const string InternetClientCapability = "S-1-15-3-1";

    public SecurityIdentifier Sid { get; }
    private GameSandbox(SecurityIdentifier sid) => Sid = sid;

    public static GameSandbox Open()
    {
        int hr = CreateAppContainerProfile(ProfileName, "Token Vault Minecraft sandbox",
            "Runs modded Minecraft without access to your files, credentials or the Token Vault process.", IntPtr.Zero, 0, out IntPtr sid);
        if (hr == unchecked((int)0x800700B7)) hr = DeriveAppContainerSidFromAppContainerName(ProfileName, out sid); // already exists
        if (hr < 0) throw new UserVisibleException($"Could not create the Windows AppContainer sandbox (0x{hr:X8}).");
        try { return new GameSandbox(new SecurityIdentifier(sid)); }
        finally { FreeSid(sid); }
    }

    // ---- Loopback: the game must reach the vault's 127.0.0.1 listeners. Windows blocks loopback for
    // AppContainers unless an exemption exists for that specific container SID. Adding one needs admin once.

    // null: Windows would not report the list (the game will still fail closed if loopback is blocked).
    public bool? HasLoopbackExemption()
    {
        uint error = NetworkIsolationGetAppContainerConfig(out uint count, out IntPtr array);
        if (error != 0) return null;
        // The API does not document a matching free function; this small list is read rarely, so it is not freed.
        int size = Marshal.SizeOf<SidAndAttributes>();
        for (int i = 0; i < count; i++)
        {
            var entry = Marshal.PtrToStructure<SidAndAttributes>(array + i * size);
            if (entry.Sid != IntPtr.Zero && new SecurityIdentifier(entry.Sid) == Sid) return true;
        }
        return false;
    }

    // The drive root must let this sandbox list folder names, or Java can't resolve any path (see AppPaths.GameRoot).
    public bool HasDriveRootListing() => HasListGrant(new DirectoryInfo(Path.GetPathRoot(AppPaths.GameRoot)!).GetAccessControl());

    // false: a one-time step is missing. null: Windows wouldn't report the loopback list. All steps need administrator
    // approval, so they are done together.
    public bool? IsSetUp() => !HasDriveRootListing() || !IsLowLabeled(AppPaths.GameRoot) ? false : HasLoopbackExemption();

    public async Task<bool> RequestSetupAsync()
    {
        // Built-in Windows tools, one elevated run:
        //  * CheckNetIsolation adds this one sandbox to the loopback exemption list (other entries are preserved);
        //  * icacls lets this one sandbox list the names in the drive root (this folder only; no file contents);
        //  * icacls gives the game root a low integrity label (see GameFolders) when Token Vault couldn't do it itself,
        //    e.g. for a folder created by an earlier build. Labels don't grant access; folder permissions still decide.
        string system = Environment.SystemDirectory, drive = Path.GetPathRoot(AppPaths.GameRoot)!, icacls = Path.Combine(system, "icacls.exe");
        string commands = $"\"{Path.Combine(system, "CheckNetIsolation.exe")}\" LoopbackExempt -a -p={Sid.Value} & " +
                          $"\"{icacls}\" \"{drive}.\" /grant \"*{Sid.Value}:(S,RD,X,RA)\"";
        if (!IsLowLabeled(AppPaths.GameRoot) && Directory.Exists(AppPaths.GameRoot))
            commands += $" & \"{icacls}\" \"{AppPaths.GameRoot}\" /setintegritylevel (OI)(CI)L /T /C /Q";
        var info = new ProcessStartInfo(Path.Combine(system, "cmd.exe"), "/d /c \"" + commands + "\"")
            { UseShellExecute = true, Verb = "runas", WindowStyle = ProcessWindowStyle.Hidden };
        try
        {
            using var process = Process.Start(info);
            if (process is not null) await process.WaitForExitAsync();
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 1223) { return false; } // user declined the UAC prompt
        catch (Win32Exception ex) { throw Failed("ask Windows for administrator approval", ex.NativeErrorCode); }
        return IsSetUp() != false;
    }

    // ---- File access. Grants are inheritable and applied only when missing: once the sandbox can write a
    // folder we never re-propagate permissions into it, so links a mod plants there are never followed.

    public void GrantRead(string directory) => Grant(directory, FileSystemRights.ReadAndExecute, write: false);
    public void GrantWrite(string directory) => Grant(directory, FileSystemRights.Modify, write: true);

    private const FileSystemRights WriteBits = FileSystemRights.WriteData | FileSystemRights.AppendData | FileSystemRights.WriteExtendedAttributes |
        FileSystemRights.WriteAttributes | FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles |
        FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership;

    // Takes back every right the sandbox was given directly on this folder (and, through inheritance, inside it) when one
    // of them allows writing. Removing rights only narrows access, so following a planted link here can't widen anything.
    // Read access is granted again afterwards where it is needed.
    public void RevokeWrite(string directory)
    {
        var info = new DirectoryInfo(directory);
        if (!info.Exists) return;
        var acl = info.GetAccessControl();
        bool writable = false;
        foreach (FileSystemAccessRule rule in acl.GetAccessRules(true, false, typeof(SecurityIdentifier)))
            if (rule.AccessControlType == AccessControlType.Allow && rule.IdentityReference == Sid && (rule.FileSystemRights & WriteBits) != 0)
                writable = true;
        if (!writable) return;
        acl.PurgeAccessRules(Sid);
        info.SetAccessControl(acl);
    }

    // Refuses a folder tree that contains a link or junction anywhere. Used before permissions are propagated into a
    // folder that something sandboxed could once write, so a planted link can't carry a grant somewhere else.
    // (Windows itself stops a sandboxed process from hard-linking files it can't write.)
    public static void RequireNoLinks(string directory)
    {
        var pending = new Stack<DirectoryInfo>([new DirectoryInfo(directory)]);
        while (pending.TryPop(out var dir))
        {
            if (!dir.Exists) continue;
            foreach (var entry in dir.EnumerateFileSystemInfos("*", new EnumerationOptions { RecurseSubdirectories = false, AttributesToSkip = 0, IgnoreInaccessible = false }))
            {
                if ((entry.Attributes & FileAttributes.ReparsePoint) != 0)
                    throw new UserVisibleException($"{entry.FullName} is a link, which Token Vault doesn't allow in game folders. Delete {directory} and press Play to reinstall it.");
                if (entry is DirectoryInfo child) pending.Push(child);
            }
        }
    }

    // Java (24+) resolves real paths by listing every parent folder. The sandbox may list folder NAMES along the chain
    // from the game root to each shared folder (this folder only, nothing inherited); file contents stay governed by
    // the grants above. Synchronize is required: Windows opens folders for listing with it.
    private const FileSystemRights ListOnly = FileSystemRights.ListDirectory | FileSystemRights.Traverse |
                                              FileSystemRights.ReadAttributes | FileSystemRights.Synchronize;

    private void GrantParents(string directory)
    {
        string root = SandboxPolicy.Normalize(AppPaths.GameRoot);
        for (string? dir = Path.GetDirectoryName(SandboxPolicy.Normalize(directory));
             dir is not null && (SandboxPolicy.Same(dir, root) || SandboxPolicy.IsWithin(dir, root));
             dir = Path.GetDirectoryName(dir))
        {
            var info = new DirectoryInfo(dir);
            if ((info.Attributes & FileAttributes.ReparsePoint) != 0) throw new UserVisibleException("Game folders cannot be links or junctions: " + dir);
            var acl = info.GetAccessControl();
            if (HasListGrant(acl)) continue;
            acl.AddAccessRule(new FileSystemAccessRule(Sid, ListOnly, InheritanceFlags.None, PropagationFlags.None, AccessControlType.Allow));
            info.SetAccessControl(acl);
        }
    }

    private bool HasListGrant(DirectorySecurity acl)
    {
        foreach (FileSystemAccessRule rule in acl.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            if (rule.AccessControlType == AccessControlType.Allow && rule.IdentityReference == Sid &&
                (rule.FileSystemRights & ListOnly) == ListOnly && (rule.PropagationFlags & PropagationFlags.InheritOnly) == 0)
                return true;
        return false;
    }

    private void Grant(string directory, FileSystemRights rights, bool write)
    {
        var info = new DirectoryInfo(directory);
        if (!info.Exists) throw new DirectoryNotFoundException("Folder not found: " + directory);
        if ((info.Attributes & FileAttributes.ReparsePoint) != 0)
            throw new UserVisibleException("Sandbox folders cannot be links or junctions: " + directory);
        if (SandboxPolicy.IsWithin(directory, AppPaths.GameRoot)) GrantParents(directory);
        var acl = info.GetAccessControl();
        if (HasGrant(acl, rights, write)) return;
        // Low integrity label: an AppContainer process cannot write medium-integrity objects even if the DACL allows it.
        // Folders under the game root inherit the root's label, so this only runs for folders outside it.
        if (write && !IsLowLabeled(directory)) SetLowIntegrityLabel(directory);
        acl.AddAccessRule(new FileSystemAccessRule(Sid, rights, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None, AccessControlType.Allow));
        try { info.SetAccessControl(acl); }
        catch (UnauthorizedAccessException)
        {
            throw new UserVisibleException($"Windows did not allow Token Vault to share {directory} with the sandbox. " +
                "Use folders under your user profile (or Java under Program Files).");
        }
    }

    private bool HasGrant(DirectorySecurity acl, FileSystemRights rights, bool write)
    {
        foreach (FileSystemAccessRule rule in acl.GetAccessRules(true, true, typeof(SecurityIdentifier)))
        {
            bool who = rule.IdentityReference == Sid || (!write && rule.IdentityReference == AllApplicationPackages);
            bool inherits = rule.IsInherited || rule.InheritanceFlags == (InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit);
            if (rule.AccessControlType == AccessControlType.Allow && who && inherits && (rule.FileSystemRights & rights) == rights) return true;
        }
        return false;
    }

    // True when the folder carries an inheritable low label, set on it or inherited from a parent.
    public static bool IsLowLabeled(string directory)
    {
        if (GetNamedSecurityInfoW(directory, 1 /* SE_FILE_OBJECT */, 0x10 /* LABEL_SECURITY_INFORMATION */,
                IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out IntPtr descriptor) != 0)
            return false;
        try
        {
            if (!ConvertSecurityDescriptorToStringSecurityDescriptorW(descriptor, 1, 0x10, out IntPtr text, IntPtr.Zero)) return false;
            try { return System.Text.RegularExpressions.Regex.IsMatch(Marshal.PtrToStringUni(text) ?? "", @"\(ML;OICI(ID)?;NW;;;LW\)"); }
            finally { LocalFree(text); }
        }
        finally { LocalFree(descriptor); }
    }

    public static void SetLowIntegrityLabel(string directory)
    {
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW("S:(ML;OICI;NW;;;LW)", 1, out IntPtr descriptor, IntPtr.Zero))
            throw Failed("prepare a folder for the sandbox");
        try
        {
            if (!GetSecurityDescriptorSacl(descriptor, out _, out IntPtr sacl, out _)) throw Failed("prepare a folder for the sandbox");
            uint error = SetNamedSecurityInfoW(directory, 1 /* SE_FILE_OBJECT */, 0x10 /* LABEL_SECURITY_INFORMATION */,
                IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, sacl);
            if (error != 0) throw Failed("let the sandbox write to " + directory, (int)error);
        }
        finally { LocalFree(descriptor); }
    }

    // ---- Process creation.

    // output: optional file that receives the process's stdout/stderr. It is the ONLY handle the process inherits.
    public SandboxedProcess Start(string executable, IReadOnlyList<string> arguments, string workingDirectory,
        IReadOnlyDictionary<string, string> environment, bool allowClipboard, SafeFileHandle? output = null)
    {
        byte[] containerSid = new byte[Sid.BinaryLength];
        Sid.GetBinaryForm(containerSid, 0);
        var pinned = GCHandle.Alloc(containerSid, GCHandleType.Pinned);
        IntPtr capability = IntPtr.Zero, capabilities = IntPtr.Zero, securityCapabilities = IntPtr.Zero,
            attributes = IntPtr.Zero, environmentBlock = IntPtr.Zero, handleList = IntPtr.Zero;
        bool attributesInitialized = false;
        try
        {
            // internetClient only: outbound internet (skins, resource packs). No inbound, no LAN server role.
            if (!ConvertStringSidToSidW(InternetClientCapability, out capability)) throw Failed("set up the sandbox");
            capabilities = Marshal.AllocHGlobal(Marshal.SizeOf<SidAndAttributes>());
            Marshal.StructureToPtr(new SidAndAttributes { Sid = capability, Attributes = 0x4 /* SE_GROUP_ENABLED */ }, capabilities, false);
            securityCapabilities = Marshal.AllocHGlobal(Marshal.SizeOf<SecurityCapabilities>());
            Marshal.StructureToPtr(new SecurityCapabilities
            { AppContainerSid = pinned.AddrOfPinnedObject(), Capabilities = capabilities, CapabilityCount = 1 }, securityCapabilities, false);

            IntPtr size = IntPtr.Zero;
            int attributeCount = output is null ? 1 : 2;
            InitializeProcThreadAttributeList(IntPtr.Zero, attributeCount, 0, ref size);
            attributes = Marshal.AllocHGlobal(size);
            if (!InitializeProcThreadAttributeList(attributes, attributeCount, 0, ref size)) throw Failed("set up the sandbox");
            attributesInitialized = true;
            if (!UpdateProcThreadAttribute(attributes, 0, (IntPtr)0x00020009 /* SECURITY_CAPABILITIES */, securityCapabilities,
                    (IntPtr)Marshal.SizeOf<SecurityCapabilities>(), IntPtr.Zero, IntPtr.Zero))
                throw Failed("set up the sandbox");

            var startup = new StartupInfoEx { Attributes = attributes };
            startup.StartupInfo.cb = Marshal.SizeOf<StartupInfoEx>();
            if (output is not null)
            {
                if (!SetHandleInformation(output, 1 /* HANDLE_FLAG_INHERIT */, 1)) throw Failed("set up the game log");
                handleList = Marshal.AllocHGlobal(IntPtr.Size);
                Marshal.WriteIntPtr(handleList, output.DangerousGetHandle());
                if (!UpdateProcThreadAttribute(attributes, 0, (IntPtr)0x00020002 /* HANDLE_LIST */, handleList, IntPtr.Size, IntPtr.Zero, IntPtr.Zero))
                    throw Failed("set up the game log");
                startup.StartupInfo.Flags = 0x100; // STARTF_USESTDHANDLES
                startup.StartupInfo.StdOutput = startup.StartupInfo.StdError = output.DangerousGetHandle();
            }
            environmentBlock = Marshal.StringToHGlobalUni(string.Concat(environment
                .OrderBy(p => p.Key, StringComparer.OrdinalIgnoreCase).Select(p => p.Key + "=" + p.Value + "\0")) + "\0");
            var commandLine = new System.Text.StringBuilder(WindowsCommandLine.Build(executable, arguments));
            const uint flags = 0x00080000 /* EXTENDED_STARTUPINFO_PRESENT */ | 0x4 /* CREATE_SUSPENDED */ |
                               0x400 /* CREATE_UNICODE_ENVIRONMENT */ | 0x08000000 /* CREATE_NO_WINDOW */;
            const uint breakaway = 0x01000000; // CREATE_BREAKAWAY_FROM_JOB
            // Token Vault itself may run inside a job (some shells, browsers and game clients start programs in one).
            // The game then leaves that job when allowed, so it can be put in its own restricted job below; otherwise
            // Windows nests our job inside the inherited one.
            bool inJob = IsProcessInJob(GetCurrentProcess(), IntPtr.Zero, out bool member) && member;
            // Inheritance is limited by HANDLE_LIST to the output file; without one, nothing is inherited.
            ProcessInformation process;
            bool created = CreateProcessW(executable, new System.Text.StringBuilder(commandLine.ToString()), IntPtr.Zero, IntPtr.Zero,
                output is not null, flags | (inJob ? breakaway : 0), environmentBlock, workingDirectory, ref startup, out process);
            int error = created ? 0 : Marshal.GetLastWin32Error();
            if (!created && inJob && error == 5 /* breakaway not allowed */)
            {
                created = CreateProcessW(executable, commandLine, IntPtr.Zero, IntPtr.Zero, output is not null, flags, environmentBlock,
                    workingDirectory, ref startup, out process);
                error = created ? 0 : Marshal.GetLastWin32Error();
            }
            if (!created) throw Failed("start Java in the sandbox", error);
            var processHandle = new SafeProcessHandle(process.Process, ownsHandle: true);
            using var thread = new SafeProcessHandle(process.Thread, ownsHandle: true);
            SafeJobHandle? job = null;
            try
            {
                job = CreateJob(allowClipboard);
                if (!AssignProcessToJobObject(job, processHandle)) throw Failed("put the game in its sandbox job");
                if (ResumeThread(thread) == uint.MaxValue) throw Failed("start the game");
                return new SandboxedProcess(processHandle, job);
            }
            catch
            {
                TerminateProcess(processHandle, 1);
                processHandle.Dispose(); job?.Dispose();
                throw;
            }
        }
        finally
        {
            if (attributesInitialized) DeleteProcThreadAttributeList(attributes);
            if (attributes != IntPtr.Zero) Marshal.FreeHGlobal(attributes);
            if (securityCapabilities != IntPtr.Zero) Marshal.FreeHGlobal(securityCapabilities);
            if (capabilities != IntPtr.Zero) Marshal.FreeHGlobal(capabilities);
            if (capability != IntPtr.Zero) LocalFree(capability);
            if (environmentBlock != IntPtr.Zero) Marshal.FreeHGlobal(environmentBlock);
            if (handleList != IntPtr.Zero) Marshal.FreeHGlobal(handleList);
            if (output is not null) SetHandleInformation(output, 1, 0);
            pinned.Free();
        }
    }

    private static SafeJobHandle CreateJob(bool allowClipboard)
    {
        var job = CreateJobObjectW(IntPtr.Zero, null);
        if (job.IsInvalid) throw Failed("create the sandbox job");
        // Everything the game starts stays in the job and dies with it (or with Token Vault).
        var limits = new JobExtendedLimitInformation();
        limits.Basic.LimitFlags = 0x2000 /* KILL_ON_JOB_CLOSE */ | 0x400 /* DIE_ON_UNHANDLED_EXCEPTION */;
        uint ui = 0x40 /* UILIMIT_DESKTOP */ | 0x80 /* UILIMIT_EXITWINDOWS */;
        // Clipboard off by default: passwords copied from a password manager while playing stay out of reach.
        if (!allowClipboard) ui |= 0x2 /* UILIMIT_READCLIPBOARD */ | 0x4 /* UILIMIT_WRITECLIPBOARD */;
        if (!SetInformationJobObject(job, 9 /* ExtendedLimitInformation */, ref limits, Marshal.SizeOf<JobExtendedLimitInformation>()) ||
            !SetInformationJobObject(job, 4 /* BasicUIRestrictions */, ref ui, sizeof(uint)))
        {
            var error = Failed("restrict the sandbox job");
            job.Dispose();
            throw error;
        }
        return job;
    }

    // Windows' own description of the error (no paths or account data), plus the step that failed.
    private static UserVisibleException Failed(string step, int error = 0)
    {
        if (error == 0) error = Marshal.GetLastWin32Error();
        string hint = error is 5 or 1260 ? " Security software or a company policy may be blocking it." : "";
        return new UserVisibleException($"Couldn't {step}: {new Win32Exception(error).Message} (Windows error {error}).{hint}");
    }

    [StructLayout(LayoutKind.Sequential)] private struct SidAndAttributes { public IntPtr Sid; public uint Attributes; }
    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityCapabilities { public IntPtr AppContainerSid; public IntPtr Capabilities; public uint CapabilityCount; public uint Reserved; }
    [StructLayout(LayoutKind.Sequential)]
    private struct StartupInfo
    {
        public int cb; public IntPtr Reserved, Desktop, Title;
        public int X, Y, XSize, YSize, XCountChars, YCountChars, FillAttribute, Flags;
        public short ShowWindow, Reserved2Count; public IntPtr Reserved2, StdInput, StdOutput, StdError;
    }
    [StructLayout(LayoutKind.Sequential)] private struct StartupInfoEx { public StartupInfo StartupInfo; public IntPtr Attributes; }
    [StructLayout(LayoutKind.Sequential)] private struct ProcessInformation { public IntPtr Process, Thread; public uint ProcessId, ThreadId; }
    [StructLayout(LayoutKind.Sequential)]
    private struct JobBasicLimitInformation
    {
        public long PerProcessUserTimeLimit, PerJobUserTimeLimit; public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize, MaximumWorkingSetSize; public uint ActiveProcessLimit;
        public UIntPtr Affinity; public uint PriorityClass, SchedulingClass;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct JobExtendedLimitInformation
    {
        public JobBasicLimitInformation Basic; public ulong ReadOps, WriteOps, OtherOps, ReadBytes, WriteBytes, OtherBytes;
        public UIntPtr ProcessMemoryLimit, JobMemoryLimit, PeakProcessMemoryUsed, PeakJobMemoryUsed;
    }

    [DllImport("userenv.dll", CharSet = CharSet.Unicode)]
    private static extern int CreateAppContainerProfile(string name, string displayName, string description, IntPtr capabilities, uint count, out IntPtr sid);
    [DllImport("userenv.dll", CharSet = CharSet.Unicode)]
    private static extern int DeriveAppContainerSidFromAppContainerName(string name, out IntPtr sid);
    [DllImport("advapi32.dll")] private static extern IntPtr FreeSid(IntPtr sid);
    [DllImport("FirewallAPI.dll")] private static extern uint NetworkIsolationGetAppContainerConfig(out uint count, out IntPtr sids);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool ConvertStringSidToSidW(string sid, out IntPtr result);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string sddl, uint revision, out IntPtr descriptor, IntPtr size);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetSecurityDescriptorSacl(IntPtr descriptor, out bool present, out IntPtr sacl, out bool defaulted);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    private static extern uint SetNamedSecurityInfoW(string name, int type, uint information, IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    private static extern uint GetNamedSecurityInfoW(string name, int type, uint information, IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl, out IntPtr descriptor);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool ConvertSecurityDescriptorToStringSecurityDescriptorW(IntPtr descriptor, uint revision, uint information, out IntPtr text, IntPtr length);
    [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr memory);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool InitializeProcThreadAttributeList(IntPtr list, int count, int flags, ref IntPtr size);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool UpdateProcThreadAttribute(IntPtr list, uint flags, IntPtr attribute, IntPtr value, IntPtr size, IntPtr previous, IntPtr returnSize);
    [DllImport("kernel32.dll")] private static extern void DeleteProcThreadAttributeList(IntPtr list);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CreateProcessW(string application, System.Text.StringBuilder commandLine, IntPtr processAttributes, IntPtr threadAttributes,
        bool inheritHandles, uint flags, IntPtr environment, string currentDirectory, ref StartupInfoEx startup, out ProcessInformation information);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern SafeJobHandle CreateJobObjectW(IntPtr attributes, string? name);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetInformationJobObject(SafeJobHandle job, int infoClass, ref JobExtendedLimitInformation info, int length);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetInformationJobObject(SafeJobHandle job, int infoClass, ref uint info, int length);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool AssignProcessToJobObject(SafeJobHandle job, SafeProcessHandle process);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern uint ResumeThread(SafeProcessHandle thread);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool SetHandleInformation(SafeFileHandle handle, uint mask, uint flags);
    [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool TerminateProcess(SafeProcessHandle process, uint exitCode);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool IsProcessInJob(IntPtr process, IntPtr job, out bool result);
    [DllImport("kernel32.dll")] private static extern IntPtr GetCurrentProcess();
}

[SupportedOSPlatform("windows")]
public sealed class SafeJobHandle() : SafeHandleZeroOrMinusOneIsInvalid(ownsHandle: true)
{
    protected override bool ReleaseHandle() => CloseHandle(handle);
    [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr handle);
}

[SupportedOSPlatform("windows")]
public sealed class SandboxedProcess(SafeProcessHandle process, SafeJobHandle job) : IDisposable
{
    public async Task<int> WaitForExitAsync(CancellationToken ct)
    {
        var exited = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var wait = new ManualResetEvent(false) { SafeWaitHandle = new SafeWaitHandle(process.DangerousGetHandle(), ownsHandle: false) };
        var registration = ThreadPool.RegisterWaitForSingleObject(wait, (_, _) => exited.TrySetResult(), null, Timeout.Infinite, executeOnlyOnce: true);
        try { await exited.Task.WaitAsync(ct); }
        finally { registration.Unregister(null); }
        return GetExitCodeProcess(process, out uint code) ? unchecked((int)code) : -1;
    }

    // Terminates the game and anything it started.
    public void Kill() => TerminateJobObject(job, 1);

    // True when the process with this id is the game or something it started (members of the game's job).
    public bool Contains(int processId)
    {
        using var handle = OpenProcess(0x1000 /* PROCESS_QUERY_LIMITED_INFORMATION */, false, processId);
        return !handle.IsInvalid && IsProcessInJob(handle, job, out bool member) && member;
    }

    public void Dispose() { Kill(); job.Dispose(); process.Dispose(); }

    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool GetExitCodeProcess(SafeProcessHandle process, out uint code);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool TerminateJobObject(SafeJobHandle job, uint exitCode);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern SafeProcessHandle OpenProcess(uint access, bool inherit, int processId);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool IsProcessInJob(SafeProcessHandle process, SafeJobHandle job, out bool result);
}
