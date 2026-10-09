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

// Asks the player (in Token Vault's own window, which the sandboxed game cannot click) whether a join is theirs.
public delegate Task<bool> JoinApproval(ServerEntry server, CancellationToken ct);

// One broker per server the player added in Token Vault. It authenticates only connections to that server, only
// one game connection at a time across all brokers (shared slot), and optionally only after the player approves.
// protocol: the client's network protocol (Minecraft 1.8 = 47 ... 26.1.2 = 775). The login packets differ by version:
//   1.16 (735)    Login Success carries the UUID as 16 bytes instead of a string
//   1.19 (759/760) Encryption Response has a "has verify token" flag
//   1.20.2 (764)  the client acknowledges Login Success before the game starts
//   1.20.5 (766)  Encryption Request says whether the server authenticates; cookie requests exist
public sealed class ConnectionBroker(ServerEntry target, PlayerProfile profile,
    IConnectionAuthenticator authenticator, Action<string> audit, JoinApproval? approve = null, SemaphoreSlim? slot = null,
    int protocol = 775)
{
    private readonly SemaphoreSlim oneConnection = slot ?? new(1, 1);
    private long lastLogin;

    // Loopback only, on a port Windows picks, so nothing collides with other software.
    public static TcpListener Listen()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Server.ExclusiveAddressUse = true;
        listener.Start(4);
        return listener;
    }

    public async Task RunAsync(TcpListener listener, CancellationToken ct)
    {
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
        if (PacketIO.ReadVarInt(handshake, ref offset) != 0 || PacketIO.ReadVarInt(handshake, ref offset) != protocol || protocol < 47)
            throw new InvalidDataException("Unsupported protocol.");
        // The address the game typed is NEVER used to pick the destination. Only a mod-loader marker after a NUL
        // (Forge "\0FML2\0"/"\0FML3\0", NeoForge) is carried over, so modded servers recognise the client.
        string marker = LoaderMarker(PacketIO.ReadString(handshake, ref offset, 255));
        if (offset + 2 > handshake.Length) throw new InvalidDataException("Truncated handshake.");
        offset += 2;
        int state = PacketIO.ReadVarInt(handshake, ref offset);
        PacketIO.RequireEnd(handshake, offset);
        if (state == 1) { await StatusAsync(downstream, marker, ct); return; }
        if (state != 2) throw new InvalidDataException("Unsupported intention (including transfer).");
        if (!await oneConnection.WaitAsync(0, ct))
        {
            audit("broker:busy:" + target.Host);
            throw new InvalidOperationException("A game connection is already active.");
        }
        try
        {
            long now = Environment.TickCount64;
            if (now - lastLogin < 3000 && lastLogin != 0) throw new InvalidOperationException("Reconnect rate limited.");
            lastLogin = now;
            // The game's Login Start is checked (it must be this account) and then forwarded as-is, so version-specific
            // fields such as 1.19's signed profile key reach the server unchanged.
            var start = await PacketIO.ReadAsync(downstream, -1, ct);
            CheckLoginStart(start);
            if (approve is not null)
            {
                bool approved;
                using (var answer = CancellationTokenSource.CreateLinkedTokenSource(ct))
                {
                    answer.CancelAfter(TimeSpan.FromSeconds(25)); // the game gives up on a login after ~30 s
                    try { approved = await approve(target, answer.Token); }
                    catch (OperationCanceledException) when (!lifetime.IsCancellationRequested) { approved = false; }
                }
                if (!approved)
                {
                    audit("broker:blocked:" + target.Host);
                    string reason = System.Text.Json.JsonSerializer.Serialize(new { text = "Token Vault blocked this join. Approve it in the Token Vault window to sign in." });
                    await PacketIO.WriteAsync(downstream, PacketIO.Packet(0, s => PacketIO.WriteString(s, reason)), -1, lifetime);
                    return;
                }
                audit("broker:approved:" + target.Host);
            }
            using var remote = new TcpClient { NoDelay = true };
            await remote.ConnectAsync(target.Host, target.Port, ct);
            Stream upstream = remote.GetStream();
            CipherStream? encrypted = null;
            try
            {
                await PacketIO.WriteAsync(upstream, PacketIO.Handshake(target.Host + marker, target.Port, 2, protocol), -1, ct);
                await PacketIO.WriteAsync(upstream, start, -1, ct);
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
                        if (protocol >= 766 && (offset >= packet.Length || packet[offset++] != 1))
                            throw new InvalidDataException("Upstream must require online authentication.");
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
                                if (protocol is 759 or 760) s.WriteByte(1); // 1.19-1.19.2: "has verify token"
                                PacketIO.WriteBytes(s, rsa.Encrypt(verify, RSAEncryptionPadding.Pkcs1));
                            }), -1, ct);
                            encrypted = new CipherStream(upstream, secret);
                            upstream = encrypted;
                            authenticated = true;
                            audit("broker:authenticated:" + target.Host);
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
                        if (protocol >= 735)
                        {
                            if (packet.Length - offset < 16 || !packet.AsSpan(offset, 16).SequenceEqual(Convert.FromHexString(profile.Id)))
                                throw new InvalidDataException("Upstream returned a different account.");
                            offset += 16;
                        }
                        else if (PacketIO.ReadString(packet, ref offset, 36).Replace("-", "") is var uuid && !uuid.Equals(profile.Id, StringComparison.OrdinalIgnoreCase))
                            throw new InvalidDataException("Upstream returned a different account.");
                        if (PacketIO.ReadString(packet, ref offset, 16) != profile.Name) throw new InvalidDataException("Upstream returned a different name.");
                        await PacketIO.WriteAsync(downstream, packet, compression, ct);
                        if (protocol >= 764)
                        {
                            byte[] ack = await PacketIO.ReadAsync(downstream, compression, ct);
                            if (ack.Length != 1 || ack[0] != 3) throw new InvalidDataException("Expected login acknowledgement.");
                            await PacketIO.WriteAsync(upstream, ack, compression, ct);
                        }
                        loginDeadline.CancelAfter(Timeout.InfiniteTimeSpan);
                        using var relay = CancellationTokenSource.CreateLinkedTokenSource(lifetime);
                        Task outgoing = downstream.CopyToAsync(upstream, 65536, relay.Token);
                        Task incoming = upstream.CopyToAsync(downstream, 65536, relay.Token);
                        await Task.WhenAny(outgoing, incoming);
                        relay.Cancel();
                        try { await Task.WhenAll(outgoing, incoming); } catch (OperationCanceledException) { }
                        return;
                    }
                    if ((id == 4 && protocol >= 393) || (id == 5 && protocol >= 766))
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

    // Login Start always begins with the player name. From 1.19.1 it can carry the UUID (always from 1.20.2): it must be ours.
    private void CheckLoginStart(byte[] start)
    {
        int offset = 0;
        if (PacketIO.ReadVarInt(start, ref offset) != 0 || PacketIO.ReadString(start, ref offset, 16) != profile.Name)
            throw new InvalidDataException("Wrong local profile.");
        ReadOnlySpan<byte> id = Convert.FromHexString(profile.Id);
        if (protocol >= 764)
        {
            if (start.Length - offset != 16 || !start.AsSpan(offset).SequenceEqual(id)) throw new InvalidDataException("Wrong local profile.");
        }
        else if (protocol is >= 761 and <= 763)
        {
            if (offset >= start.Length) throw new InvalidDataException("Truncated login.");
            bool hasId = start[offset++] == 1;
            if (hasId && (start.Length - offset != 16 || !start.AsSpan(offset).SequenceEqual(id))) throw new InvalidDataException("Wrong local profile.");
            if (!hasId && offset != start.Length) throw new InvalidDataException("Unexpected login fields.");
        }
        else if (protocol < 759 && offset != start.Length) throw new InvalidDataException("Unexpected login fields.");
        // 1.19/1.19.2 (759/760): signed profile-key data (and on 760 an optional UUID) follow; the server verifies them.
        if (start.Length > 4096) throw new InvalidDataException("Login Start too large.");
    }

    public static string LoaderMarker(string host)
    {
        int nul = host.IndexOf('\0');
        if (nul < 0) return "";
        string marker = host[nul..];
        return marker.Length <= 32 && marker.All(ch => ch == '\0' || char.IsAsciiLetterOrDigit(ch)) ? marker : "";
    }

    private async Task StatusAsync(Stream stream, string marker, CancellationToken ct)
    {
        byte[] request = await PacketIO.ReadAsync(stream, -1, ct);
        if (request.Length != 1 || request[0] != 0) throw new InvalidDataException("Invalid status request.");
        byte[] response = await UpstreamStatusAsync(marker, ct) ?? PacketIO.Packet(0, s => PacketIO.WriteString(s, JsonSerializer.Serialize(new
        {
            version = new { name = "Token Vault", protocol },
            players = new { max = 0, online = 0 },
            description = new { text = target.Name + " (could not reach the server)" }
        })));
        await PacketIO.WriteAsync(stream, response, -1, ct);
        byte[] ping = await PacketIO.ReadAsync(stream, -1, ct);
        if (ping.Length == 9 && ping[0] == 1) await PacketIO.WriteAsync(stream, ping, -1, ct);
    }

    // Server-list ping (MOTD, player count). Unauthenticated and unencrypted; only the response packet is relayed.
    private async Task<byte[]?> UpstreamStatusAsync(string marker, CancellationToken lifetime)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(lifetime);
        deadline.CancelAfter(TimeSpan.FromSeconds(5));
        try
        {
            using var remote = new TcpClient { NoDelay = true };
            await remote.ConnectAsync(target.Host, target.Port, deadline.Token);
            var upstream = remote.GetStream();
            await PacketIO.WriteAsync(upstream, PacketIO.Handshake(target.Host + marker, target.Port, 1, protocol), -1, deadline.Token);
            await PacketIO.WriteAsync(upstream, [0], -1, deadline.Token);
            byte[] response = await PacketIO.ReadAsync(upstream, -1, deadline.Token);
            int offset = 0;
            if (PacketIO.ReadVarInt(response, ref offset) != 0) return null;
            _ = PacketIO.ReadString(response, ref offset);
            PacketIO.RequireEnd(response, offset);
            return response;
        }
        catch (Exception ex) when (ex is IOException or SocketException or InvalidDataException or OperationCanceledException)
        {
            if (lifetime.IsCancellationRequested) throw;
            return null;
        }
    }
}
