namespace TokenVault.Vault;

public sealed class AuditLog(string path) : IDisposable
{
    private readonly object gate = new();
    private StreamWriter writer = Open(path);
    private static StreamWriter Open(string path) => new(new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.Read)) { AutoFlush = true };
    public void Write(string message)
    {
        lock (gate)
        {
            if (writer.BaseStream.Length >= 8 * 1024 * 1024)
            {
                writer.Dispose(); File.Move(path, path + ".previous", overwrite: true); writer = Open(path);
            }
            writer.WriteLine($"{DateTimeOffset.UtcNow:O} {message}");
        }
    }
    public void Dispose() { lock (gate) writer.Dispose(); }
}
