using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json;
using TokenVault.Core;

namespace TokenVault.Vault;

// This interface is internal to the trusted process. It is NEVER an IPC or HTTP method.
public interface IConnectionAuthenticator
{
    Task AuthorizeOwnedConnectionAsync(string serverHash, CancellationToken ct);
}

public sealed class ConnectionBroker(Configuration config, PlayerProfile profile,
    IConnectionAuthenticator authenticator, Action<string> audit)
{
    private readonly SemaphoreSlim oneConnection = new(1, 1);
    private long lastLogin;

    public async Task RunAsync(CancellationToken ct)
    {
        var listener = new TcpListener(IPAddress.Loopback, config.GamePort);
        listener.Server.ExclusiveAddressUse = true;
        listener.Start(4);
        var connections = new List<Task>();
        try
        {
            while (!ct.IsCancellationRequested)
            {
                var client = await listener.AcceptTcpClientAsync(ct);
                connections.RemoveAll(t => t.IsCompleted);
                if (connections.Count >= 4) { client.Dispose(); continue; }
                connections.Add(HandleGuardedAsync(client, ct));
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
        finally { listener.Stop(); await Task.WhenAll(connections); }
    }

    private async Task HandleGuardedAsync(TcpClient client, CancellationToken ct)
    {
        using (client)
        {
            try { await HandleAsync(client.GetStream(), ct); }
            catch (OperationCanceledException) { }
            catch (Exception ex) { audit("broker-denied:" + ex.GetType().Name); }
        }
    }

    public async Task HandleAsync(Stream downstream, CancellationToken lifetime)
    {
        using var loginDeadline = CancellationTokenSource.CreateLinkedTokenSource(lifetime);
        loginDeadline.CancelAfter(TimeSpan.FromSeconds(40));
        var ct = loginDeadline.Token;
        var handshake = await PacketIO.ReadAsync(downstream, -1, ct);
        int offset = 0;
        if (PacketIO.ReadVarInt(handshake, ref offset) != 0 || PacketIO.ReadVarInt(handshake, ref offset) != 775)
            throw new InvalidDataException("Unsupported protocol.");
        _ = PacketIO.ReadString(handshake, ref offset, 255); // NEVER used to select the upstream destination.
        if (offset + 2 > handshake.Length) throw new InvalidDataException("Truncated handshake.");
        offset += 2;
        int state = PacketIO.ReadVarInt(handshake, ref offset);
        PacketIO.RequireEnd(handshake, offset);
        if (state == 1) { await StatusAsync(downstream, ct); return; }
        if (state != 2) throw new InvalidDataException("Unsupported intention (including transfer).");
        if (!await oneConnection.WaitAsync(0, ct)) throw new InvalidOperationException("A game connection is already active.");
        try
        {
            long now = Environment.TickCount64;
            if (now - lastLogin < 3000 && lastLogin != 0) throw new InvalidOperationException("Reconnect rate limited.");
            lastLogin = now;
            var start = await PacketIO.ReadAsync(downstream, -1, ct);
            offset = 0;
            if (PacketIO.ReadVarInt(start, ref offset) != 0 || PacketIO.ReadString(start, ref offset, 16) != profile.Name ||
                start.Length - offset != 16 || !start.AsSpan(offset).SequenceEqual(Convert.FromHexString(profile.Id)))
                throw new InvalidDataException("Wrong local profile.");
            if (string.IsNullOrWhiteSpace(config.ServerHost)) throw new InvalidOperationException("No target server configured.");

            using var remote = new TcpClient { NoDelay = true };
            await remote.ConnectAsync(config.ServerHost, config.ServerPort, ct);
            Stream upstream = remote.GetStream();
            CipherStream? encrypted = null;
            try
            {
                await PacketIO.WriteAsync(upstream, PacketIO.Handshake(config.ServerHost, config.ServerPort, 2), -1, ct);
                await PacketIO.WriteAsync(upstream, PacketIO.LoginStart(profile), -1, ct);
                int compression = -1;
                bool authenticated = false;
                while (true)
                {
                    byte[] packet = await PacketIO.ReadAsync(upstream, compression, ct);
                    offset = 0;
                    int id = PacketIO.ReadVarInt(packet, ref offset);
                    if (id == 1)
                    {
                        if (authenticated || compression >= 0) throw new InvalidDataException("Unexpected encryption handshake.");
                        string serverId = PacketIO.ReadString(packet, ref offset, 20);
                        byte[] key = PacketIO.ReadBytes(packet, ref offset, 4096);
                        byte[] verify = PacketIO.ReadBytes(packet, ref offset, 256);
                        if (offset >= packet.Length || packet[offset++] != 1) throw new InvalidDataException("Upstream must require online authentication.");
                        PacketIO.RequireEnd(packet, offset);
                        using var rsa = RSA.Create();
                        rsa.ImportSubjectPublicKeyInfo(key, out int read);
                        if (read != key.Length || rsa.KeySize < 1024) throw new InvalidDataException("Invalid server RSA key.");
                        byte[] secret = RandomNumberGenerator.GetBytes(16);
                        try
                        {
                            // Both the fresh secret and upstream socket are owned here, not by the JVM.
                            string hash = MinecraftCrypto.ServerHash(serverId, secret, key);
                            await authenticator.AuthorizeOwnedConnectionAsync(hash, ct);
                            await PacketIO.WriteAsync(upstream, PacketIO.Packet(1, s =>
                            {
                                PacketIO.WriteBytes(s, rsa.Encrypt(secret, RSAEncryptionPadding.Pkcs1));
                                PacketIO.WriteBytes(s, rsa.Encrypt(verify, RSAEncryptionPadding.Pkcs1));
                            }), -1, ct);
                            encrypted = new CipherStream(upstream, secret);
                            upstream = encrypted;
                            authenticated = true;
                            audit("broker:owned-connection-authenticated");
                        }
                        finally { CryptographicOperations.ZeroMemory(secret); }
                        continue; // Encryption packet and keys NEVER forwarded to the JVM.
                    }
                    if (id == 0) { await PacketIO.WriteAsync(downstream, packet, compression, ct); return; }
                    if (id == 3)
                    {
                        if (!authenticated || compression >= 0) throw new InvalidDataException("Unexpected compression transition.");
                        int threshold = PacketIO.ReadVarInt(packet, ref offset);
                        PacketIO.RequireEnd(packet, offset);
                        if (threshold is < 0 or > PacketIO.MaxPacket) throw new InvalidDataException("Invalid compression threshold.");
                        await PacketIO.WriteAsync(downstream, packet, compression, ct);
                        compression = threshold; continue;
                    }
                    if (id == 2)
                    {
                        if (!authenticated) throw new InvalidDataException("Offline-mode upstreams are refused.");
                        if (packet.Length - offset < 16 || !packet.AsSpan(offset, 16).SequenceEqual(Convert.FromHexString(profile.Id)))
                            throw new InvalidDataException("Upstream returned a different account.");
                        offset += 16;
                        if (PacketIO.ReadString(packet, ref offset, 16) != profile.Name) throw new InvalidDataException("Upstream returned a different name.");
                        await PacketIO.WriteAsync(downstream, packet, compression, ct);
                        byte[] ack = await PacketIO.ReadAsync(downstream, compression, ct);
                        if (ack.Length != 1 || ack[0] != 3) throw new InvalidDataException("Expected login acknowledgement.");
                        await PacketIO.WriteAsync(upstream, ack, compression, ct);
                        loginDeadline.CancelAfter(Timeout.InfiniteTimeSpan);
                        using var relay = CancellationTokenSource.CreateLinkedTokenSource(lifetime);
                        Task outgoing = downstream.CopyToAsync(upstream, 65536, relay.Token);
                        Task incoming = upstream.CopyToAsync(downstream, 65536, relay.Token);
                        await Task.WhenAny(outgoing, incoming);
                        relay.Cancel();
                        try { await Task.WhenAll(outgoing, incoming); } catch (OperationCanceledException) { }
                        return;
                    }
                    if (id is 4 or 5)
                    {
                        // Fabric login plugins / cookies are data, never a generic packet-forwarding API.
                        int transaction = id == 4 ? PacketIO.ReadVarInt(packet, ref offset) : 0;
                        string? cookie = id == 5 ? PacketIO.ReadString(packet, ref offset, 256) : null;
                        await PacketIO.WriteAsync(downstream, packet, compression, ct);
                        byte[] reply = await PacketIO.ReadAsync(downstream, compression, ct);
                        int ro = 0;
                        if (PacketIO.ReadVarInt(reply, ref ro) != (id == 4 ? 2 : 4)) throw new InvalidDataException("Unexpected login response.");
                        if (id == 4 && PacketIO.ReadVarInt(reply, ref ro) != transaction) throw new InvalidDataException("Plugin transaction mismatch.");
                        if (id == 5 && PacketIO.ReadString(reply, ref ro, 256) != cookie) throw new InvalidDataException("Cookie mismatch.");
                        await PacketIO.WriteAsync(upstream, reply, compression, ct); continue;
                    }
                    throw new InvalidDataException("Unsupported login packet.");
                }
            }
            finally { encrypted?.Dispose(); }
        }
        finally { oneConnection.Release(); }
    }

    private async Task StatusAsync(Stream stream, CancellationToken ct)
    {
        byte[] request = await PacketIO.ReadAsync(stream, -1, ct);
        if (request.Length != 1 || request[0] != 0) throw new InvalidDataException("Invalid status request.");
        string json = JsonSerializer.Serialize(new
        {
            version = new { name = "26.1.2 Token Vault", protocol = 775 },
            players = new { max = 1, online = oneConnection.CurrentCount == 0 ? 1 : 0 },
            description = new { text = "Token Vault — configured server" }, enforcesSecureChat = true
        });
        await PacketIO.WriteAsync(stream, PacketIO.Packet(0, s => PacketIO.WriteString(s, json)), -1, ct);
        byte[] ping = await PacketIO.ReadAsync(stream, -1, ct);
        if (ping.Length == 9 && ping[0] == 1) await PacketIO.WriteAsync(stream, ping, -1, ct);
    }
}
