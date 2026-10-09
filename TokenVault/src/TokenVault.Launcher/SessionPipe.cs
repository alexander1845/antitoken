using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;
using TokenVault.Core;

namespace TokenVault.Launcher;

[SupportedOSPlatform("windows")]
public static class SessionPipe
{
    public static async Task<SessionDescriptor> ReadAsync(Configuration config, CancellationToken ct)
    {
        using var pipe = new NamedPipeClientStream(".", config.PipeName, PipeDirection.In, PipeOptions.Asynchronous);
        await pipe.ConnectAsync(10_000, ct);
        if (!GetNamedPipeServerProcessId(pipe.SafePipeHandle, out uint pid)) throw new IOException("Cannot identify vault process.");
        using var process = OpenProcess(0x1000, false, pid);
        if (process.IsInvalid || !OpenProcessToken(process, 0x0008, out var token)) throw new IOException("Cannot identify vault account.");
        using (token)
        using (var identity = new WindowsIdentity(token.DangerousGetHandle()))
        {
            string expected = config.HardeningMode == "separate-user" ? config.VaultUserSid : WindowsIdentity.GetCurrent().User!.Value;
            if (identity.User?.Value != expected) throw new IOException("Vault pipe is owned by the wrong Windows account.");
        }
        using var result = new MemoryStream();
        byte[] buffer = new byte[4096];
        int n;
        while ((n = await pipe.ReadAsync(buffer, ct)) != 0)
        {
            if (result.Length + n > 16384) throw new InvalidDataException("Oversize vault descriptor.");
            result.Write(buffer, 0, n);
        }
        return JsonSerializer.Deserialize<SessionDescriptor>(result.ToArray()) ?? throw new InvalidDataException("Invalid vault descriptor.");
    }
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe, out uint pid);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern SafeProcessHandle OpenProcess(uint access, bool inherit, uint pid);
    [DllImport("advapi32.dll", SetLastError = true)] private static extern bool OpenProcessToken(SafeProcessHandle process, uint access, out SafeAccessTokenHandle token);
}
