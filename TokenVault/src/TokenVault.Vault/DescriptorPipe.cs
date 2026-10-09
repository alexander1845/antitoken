using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using TokenVault.Core;

namespace TokenVault.Vault;

[SupportedOSPlatform("windows")]
public static class DescriptorPipe
{
    public static async Task RunAsync(Configuration config, SessionDescriptor descriptor, CancellationToken ct)
    {
        var security = new PipeSecurity();
        security.SetAccessRuleProtection(true, false);
        var owner = WindowsIdentity.GetCurrent().User!;
        security.SetOwner(owner);
        security.AddAccessRule(new PipeAccessRule(owner, PipeAccessRights.FullControl, AccessControlType.Allow));
        var game = new SecurityIdentifier(config.HardeningMode == "separate-user" ? config.GameUserSid : owner.Value);
        security.AddAccessRule(new PipeAccessRule(game, PipeAccessRights.Read, AccessControlType.Allow));
        // Explicitly deny network logons even if Windows exposes named pipes through SMB.
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.NetworkSid, null), PipeAccessRights.FullControl, AccessControlType.Deny));
        byte[] json = JsonSerializer.SerializeToUtf8Bytes(descriptor);
        try
        {
            while (!ct.IsCancellationRequested)
            {
                using var pipe = NamedPipeServerStreamAcl.Create(config.PipeName, PipeDirection.Out, 1,
                    PipeTransmissionMode.Byte, PipeOptions.Asynchronous | PipeOptions.FirstPipeInstance,
                    4096, 16384, security);
                await pipe.WaitForConnectionAsync(ct);
                using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
                deadline.CancelAfter(TimeSpan.FromSeconds(5));
                try { await pipe.WriteAsync(json, deadline.Token); await pipe.FlushAsync(deadline.Token); }
                catch (IOException) { }
                catch (OperationCanceledException) when (!ct.IsCancellationRequested) { }
            }
        }
        finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(json); }
    }
}
