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

    public async Task<bool> RequestLoopbackExemptionAsync()
    {
        // Built-in Windows tool; appends this one SID to the exemption list (other entries are preserved).
        var info = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "CheckNetIsolation.exe"),
            $"LoopbackExempt -a -p={Sid.Value}") { UseShellExecute = true, Verb = "runas", WindowStyle = ProcessWindowStyle.Hidden };
        try
        {
            using var process = Process.Start(info);
            if (process is not null) { await process.WaitForExitAsync(); if (process.ExitCode != 0) return false; }
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 1223) { return false; } // user declined the UAC prompt
        return HasLoopbackExemption() != false;
    }

    // ---- File access. Grants are inheritable and applied only when missing: once the sandbox can write a
    // folder we never re-propagate permissions into it, so links a mod plants there are never followed.

    public void GrantRead(string directory) => Grant(directory, FileSystemRights.ReadAndExecute, write: false);
    public void GrantWrite(string directory) => Grant(directory, FileSystemRights.Modify, write: true);

    private void Grant(string directory, FileSystemRights rights, bool write)
    {
        var info = new DirectoryInfo(directory);
        if (!info.Exists) throw new DirectoryNotFoundException("Folder not found: " + directory);
        if ((info.Attributes & FileAttributes.ReparsePoint) != 0)
            throw new UserVisibleException("Sandbox folders cannot be links or junctions: " + directory);
        var acl = info.GetAccessControl();
        if (HasGrant(acl, rights, write)) return;
        // Low integrity label: an AppContainer process cannot write medium-integrity objects even if the DACL allows it.
        if (write) SetLowIntegrityLabel(directory);
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

    private static void SetLowIntegrityLabel(string directory)
    {
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW("S:(ML;OICI;NW;;;LW)", 1, out IntPtr descriptor, IntPtr.Zero))
            throw new Win32Exception();
        try
        {
            if (!GetSecurityDescriptorSacl(descriptor, out _, out IntPtr sacl, out _)) throw new Win32Exception();
            uint error = SetNamedSecurityInfoW(directory, 1 /* SE_FILE_OBJECT */, 0x10 /* LABEL_SECURITY_INFORMATION */,
                IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, sacl);
            if (error != 0) throw new Win32Exception((int)error);
        }
        finally { LocalFree(descriptor); }
    }

    // ---- Process creation.

    public SandboxedProcess Start(string executable, IReadOnlyList<string> arguments, string workingDirectory,
        IReadOnlyDictionary<string, string> environment, bool allowClipboard)
    {
        byte[] containerSid = new byte[Sid.BinaryLength];
        Sid.GetBinaryForm(containerSid, 0);
        var pinned = GCHandle.Alloc(containerSid, GCHandleType.Pinned);
        IntPtr capability = IntPtr.Zero, capabilities = IntPtr.Zero, securityCapabilities = IntPtr.Zero,
            attributes = IntPtr.Zero, environmentBlock = IntPtr.Zero;
        bool attributesInitialized = false;
        try
        {
            // internetClient only: outbound internet (skins, resource packs). No inbound, no LAN server role.
            if (!ConvertStringSidToSidW(InternetClientCapability, out capability)) throw new Win32Exception();
            capabilities = Marshal.AllocHGlobal(Marshal.SizeOf<SidAndAttributes>());
            Marshal.StructureToPtr(new SidAndAttributes { Sid = capability, Attributes = 0x4 /* SE_GROUP_ENABLED */ }, capabilities, false);
            securityCapabilities = Marshal.AllocHGlobal(Marshal.SizeOf<SecurityCapabilities>());
            Marshal.StructureToPtr(new SecurityCapabilities
            { AppContainerSid = pinned.AddrOfPinnedObject(), Capabilities = capabilities, CapabilityCount = 1 }, securityCapabilities, false);

            IntPtr size = IntPtr.Zero;
            InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref size);
            attributes = Marshal.AllocHGlobal(size);
            if (!InitializeProcThreadAttributeList(attributes, 1, 0, ref size)) throw new Win32Exception();
            attributesInitialized = true;
            if (!UpdateProcThreadAttribute(attributes, 0, (IntPtr)0x00020009 /* SECURITY_CAPABILITIES */, securityCapabilities,
                    (IntPtr)Marshal.SizeOf<SecurityCapabilities>(), IntPtr.Zero, IntPtr.Zero))
                throw new Win32Exception();

            var startup = new StartupInfoEx { Attributes = attributes };
            startup.StartupInfo.cb = Marshal.SizeOf<StartupInfoEx>();
            environmentBlock = Marshal.StringToHGlobalUni(string.Concat(environment
                .OrderBy(p => p.Key, StringComparer.OrdinalIgnoreCase).Select(p => p.Key + "=" + p.Value + "\0")) + "\0");
            var commandLine = new System.Text.StringBuilder(WindowsCommandLine.Build(executable, arguments));
            const uint flags = 0x00080000 /* EXTENDED_STARTUPINFO_PRESENT */ | 0x4 /* CREATE_SUSPENDED */ |
                               0x400 /* CREATE_UNICODE_ENVIRONMENT */ | 0x08000000 /* CREATE_NO_WINDOW */;
            // bInheritHandles = false: the game receives no handle from this process.
            if (!CreateProcessW(executable, commandLine, IntPtr.Zero, IntPtr.Zero, false, flags, environmentBlock,
                    workingDirectory, ref startup, out ProcessInformation process))
                throw new Win32Exception();
            var processHandle = new SafeProcessHandle(process.Process, ownsHandle: true);
            using var thread = new SafeProcessHandle(process.Thread, ownsHandle: true);
            SafeJobHandle? job = null;
            try
            {
                job = CreateJob(allowClipboard);
                if (!AssignProcessToJobObject(job, processHandle)) throw new Win32Exception();
                if (ResumeThread(thread) == uint.MaxValue) throw new Win32Exception();
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
            pinned.Free();
        }
    }

    private static SafeJobHandle CreateJob(bool allowClipboard)
    {
        var job = CreateJobObjectW(IntPtr.Zero, null);
        if (job.IsInvalid) throw new Win32Exception();
        // Everything the game starts stays in the job and dies with it (or with Token Vault).
        var limits = new JobExtendedLimitInformation();
        limits.Basic.LimitFlags = 0x2000 /* KILL_ON_JOB_CLOSE */ | 0x400 /* DIE_ON_UNHANDLED_EXCEPTION */;
        uint ui = 0x40 /* UILIMIT_DESKTOP */ | 0x80 /* UILIMIT_EXITWINDOWS */;
        // Clipboard off by default: passwords copied from a password manager while playing stay out of reach.
        if (!allowClipboard) ui |= 0x2 /* UILIMIT_READCLIPBOARD */ | 0x4 /* UILIMIT_WRITECLIPBOARD */;
        if (!SetInformationJobObject(job, 9 /* ExtendedLimitInformation */, ref limits, Marshal.SizeOf<JobExtendedLimitInformation>()) ||
            !SetInformationJobObject(job, 4 /* BasicUIRestrictions */, ref ui, sizeof(uint)))
        {
            var error = new Win32Exception();
            job.Dispose();
            throw error;
        }
        return job;
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
    [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool TerminateProcess(SafeProcessHandle process, uint exitCode);
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

    public void Dispose() { Kill(); job.Dispose(); process.Dispose(); }

    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool GetExitCodeProcess(SafeProcessHandle process, out uint code);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool TerminateJobObject(SafeJobHandle job, uint exitCode);
}
