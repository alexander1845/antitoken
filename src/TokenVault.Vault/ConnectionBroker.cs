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

// Shared by every broker of one game session: one game connection at a time (across all servers), a reconnect limit,
// and the player's "Disconnect" button for the connection that is live.
public sealed class BrokerGate
{
    private readonly SemaphoreSlim slot = new(1, 1);
    private readonly object sync = new();
    private long lastLogin;
    private CancellationTokenSource? active;

    public bool TryEnter() => slot.Wait(0);
    public void Exit() { lock (sync) active = null; slot.Release(); }

    // At most one sign-in every 3 seconds, across all servers.
    public bool TryStartLogin()
    {
        lock (sync)
        {
            long now = Environment.TickCount64;
            if (lastLogin != 0 && now - lastLogin < 3000) return false;
            lastLogin = now;
            return true;
        }
    }

    internal void SetActive(CancellationTokenSource? relay) { lock (sync) active = relay; }

    // Ends the live server connection (the game shows "connection lost"). Returns false when none is live.
    public bool DisconnectActive()
    {
        lock (sync)
        {
            if (active is null) return false;
            active.Cancel();
            return true;
        }
    }
}

// Decides whether a loopback connection to a broker comes from the game's own process. Loopback is shared by every
// program and every Windows user on the PC, and a broker hands whoever connects an authenticated session, so anything
// that isn't the game is refused. Until the game is running (and whenever the check can't be made) nothing is accepted.
public sealed class ConnectionOrigin
{
    private volatile Func<IPEndPoint, IPEndPoint, bool>? isGame;
    public void Allow(Func<IPEndPoint, IPEndPoint, bool> check) => isGame = check;
    public bool IsGame(EndPoint? client, EndPoint? server)
    {
        try { return client is IPEndPoint c && server is IPEndPoint s && isGame is { } check && check(c, s); }
        catch (Exception) { return false; }
    }
}

public sealed class SessionExpiredException() : Exception("The game session's sign-in has expired.");

// One broker per server the player added in Token Vault. It authenticates only connections to that server, only
// one game connection at a time across all brokers (shared gate), and optionally only after the player approves.
// origin: when set, only connections from the game process are served. joinDeadline: no new sign-ins after it
// (connections already playing are not cut; they end when the game or Token Vault stops).
// protocol: the client's network protocol (Minecraft 1.8 = 47 ... 26.1.2 = 775). The login packets differ by version:
//   1.16 (735)    Login Success carries the UUID as 16 bytes instead of a string
//   1.19 (759/760) Encryption Response has a "has verify token" flag
//   1.20.2 (764)  the client acknowledges Login Success before the game starts
//   1.20.5 (766)  Encryption Request says whether the server authenticates; cookie requests exist
public sealed class ConnectionBroker(ServerEntry target, PlayerProfile profile,
    IConnectionAuthenticator authenticator, Action<string> audit, JoinApproval? approve = null, BrokerGate? gate = null,
    int protocol = 775, ConnectionOrigin? origin = null, DateTimeOffset? joinDeadline = null)
{
    private readonly BrokerGate gate = gate ?? new();

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
            if (origin is not null && !origin.IsGame(client.Client.RemoteEndPoint, client.Client.LocalEndPoint))
            {
                audit("broker:foreign:" + target.Host);
                return;
            }
            client.NoDelay = true; // small game packets go out at once (Nagle would hold them back and add ping)
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
        if (!gate.TryEnter())
        {
            audit("broker:busy:" + target.Host);
            throw new InvalidOperationException("A game connection is already active.");
        }
        try
        {
            // The game's Login Start is checked (it must be this account) and then forwarded as-is, so version-specific
            // fields such as 1.19's signed profile key reach the server unchanged.
            var start = await PacketIO.ReadAsync(downstream, -1, ct);
            CheckLoginStart(start);
            if (!gate.TryStartLogin())
            {
                audit("broker:ratelimited:" + target.Host);
                await Disconnect(downstream, "Token Vault: you reconnected too quickly. Wait a few seconds and try again.", -1, lifetime);
                return;
            }
            if (joinDeadline is { } deadline && DateTimeOffset.UtcNow >= deadline)
            {
                audit("broker:expired:" + target.Host);
                await Disconnect(downstream, "Token Vault: this game session's sign-in has expired. Close Minecraft and press Play again.", -1, lifetime);
                return;
            }
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
                    await Disconnect(downstream, "Token Vault blocked this join. Approve it in the Token Vault window to sign in.", -1, lifetime);
                    return;
                }
                audit("broker:approved:" + target.Host);
            }
            int compression = -1;
            bool loggedIn = false;
            CipherStream? encrypted = null;
            try
            {
                // Same packets the game itself would send: SRV lookup, then the handshake with the address as typed
                // (1.17+) or as resolved (older versions), then the game's own Login Start.
                var endpoint = await ServerResolver.ResolveAsync(target, ct);
                using var remote = new TcpClient { NoDelay = true };
                await remote.ConnectAsync(endpoint.Host, endpoint.Port, ct);
                Stream upstream = remote.GetStream();
                var (handshakeHost, handshakePort) = protocol >= 755 ? (target.Host, target.Port) : (endpoint.Host, endpoint.Port);
                await PacketIO.WriteAsync(upstream, PacketIO.Handshake(handshakeHost + marker, handshakePort, 2, protocol), -1, ct);
                await PacketIO.WriteAsync(upstream, start, -1, ct);
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
                        loggedIn = true;
                        if (protocol >= 764)
                        {
                            byte[] ack = await PacketIO.ReadAsync(downstream, compression, ct);
                            if (ack.Length != 1 || ack[0] != 3) throw new InvalidDataException("Expected login acknowledgement.");
                            await PacketIO.WriteAsync(upstream, ack, compression, ct);
                        }
                        loginDeadline.CancelAfter(Timeout.InfiniteTimeSpan);
                        using var relay = CancellationTokenSource.CreateLinkedTokenSource(lifetime);
                        gate.SetActive(relay);
                        audit("broker:connected:" + target.Host);
                        try
                        {
                            Task outgoing = downstream.CopyToAsync(upstream, 65536, relay.Token);
                            Task incoming = upstream.CopyToAsync(downstream, 65536, relay.Token);
                            await Task.WhenAny(outgoing, incoming);
                            relay.Cancel();
                            try { await Task.WhenAll(outgoing, incoming); } catch (OperationCanceledException) { } catch (IOException) { }
                        }
                        finally
                        {
                            gate.SetActive(null);
                            audit("broker:disconnected:" + target.Host);
                        }
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
            catch (Exception ex) when (!loggedIn && !lifetime.IsCancellationRequested)
            {
                // Tell the player why in the game's own disconnect screen instead of letting it time out.
                string reason = FailureReason(ex);
                audit("broker:failed:" + target.Host + ":" + ex.GetType().Name);
                try { await Disconnect(downstream, "Token Vault: " + reason, compression, lifetime); }
                catch (Exception) when (!lifetime.IsCancellationRequested) { }
                throw;
            }
            finally { encrypted?.Dispose(); }
        }
        finally { gate.Exit(); }
    }

    private static Task Disconnect(Stream downstream, string text, int compression, CancellationToken ct)
    {
        string json = JsonSerializer.Serialize(new { text });
        return PacketIO.WriteAsync(downstream, PacketIO.Packet(0, s => PacketIO.WriteString(s, json)), compression, ct);
    }

    // Plain-language reasons. No server data or exception text: only the kind of failure.
    private string FailureReason(Exception ex) => ex switch
    {
        SocketException or IOException => $"couldn't connect to {target.Host}. The server may be offline or the address may be wrong.",
        OperationCanceledException => $"{target.Host} didn't answer in time.",
        MojangJoinException mojang => mojang.Message,
        SessionExpiredException => "this game session's sign-in has expired. Close Minecraft and press Play again.",
        HttpRequestException => "couldn't reach Minecraft's sign-in service. Check your internet connection.",
        _ when ex.Message == "Upstream must require online authentication." || ex.Message == "Offline-mode upstreams are refused." =>
            $"{target.Host} is an offline-mode server. Token Vault only signs in to servers that verify accounts.",
        _ => $"the server sent something unexpected while signing in ({ex.GetType().Name})."
    };

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

    // Server list: the server's own status reply, then the game's ping goes to the server and its pong comes back, so the
    // multiplayer screen shows the real ping. If the server can't be reached, a local reply keeps the list usable.
    private async Task StatusAsync(Stream stream, string marker, CancellationToken ct)
    {
        byte[] request = await PacketIO.ReadAsync(stream, -1, ct);
        if (request.Length != 1 || request[0] != 0) throw new InvalidDataException("Invalid status request.");
        using var upstream = await UpstreamStatusAsync(marker, ct);
        byte[] response = upstream?.Response ?? PacketIO.Packet(0, s => PacketIO.WriteString(s, JsonSerializer.Serialize(new
        {
            version = new { name = "Token Vault", protocol },
            players = new { max = 0, online = 0 },
            description = new { text = target.Name + " (could not reach the server)" }
        })));
        await PacketIO.WriteAsync(stream, response, -1, ct);
        byte[] ping = await PacketIO.ReadAsync(stream, -1, ct);
        if (ping.Length != 9 || ping[0] != 1) return;
        if (upstream is not null)
        {
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
            deadline.CancelAfter(TimeSpan.FromSeconds(5));
            try
            {
                await PacketIO.WriteAsync(upstream.Stream, ping, -1, deadline.Token);
                byte[] pong = await PacketIO.ReadAsync(upstream.Stream, -1, deadline.Token);
                if (pong.Length == 9 && pong[0] == 1) { await PacketIO.WriteAsync(stream, pong, -1, ct); return; }
            }
            catch (Exception ex) when (ex is IOException or SocketException or InvalidDataException || (ex is OperationCanceledException && !ct.IsCancellationRequested)) { }
        }
        await PacketIO.WriteAsync(stream, ping, -1, ct);
    }

    private sealed class StatusConnection(TcpClient client, byte[] response) : IDisposable
    {
        public Stream Stream { get; } = client.GetStream();
        public byte[] Response { get; } = response;
        public void Dispose() => client.Dispose();
    }

    // Server-list ping (MOTD, player count). Unauthenticated and unencrypted; only status packets are relayed. The
    // connection stays open for the ping that follows.
    private async Task<StatusConnection?> UpstreamStatusAsync(string marker, CancellationToken lifetime)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(lifetime);
        deadline.CancelAfter(TimeSpan.FromSeconds(5));
        var remote = new TcpClient { NoDelay = true };
        try
        {
            var endpoint = await ServerResolver.ResolveAsync(target, deadline.Token);
            await remote.ConnectAsync(endpoint.Host, endpoint.Port, deadline.Token);
            var upstream = remote.GetStream();
            var (host, port) = protocol >= 755 ? (target.Host, target.Port) : (endpoint.Host, endpoint.Port);
            await PacketIO.WriteAsync(upstream, PacketIO.Handshake(host + marker, port, 1, protocol), -1, deadline.Token);
            await PacketIO.WriteAsync(upstream, [0], -1, deadline.Token);
            byte[] response = await PacketIO.ReadAsync(upstream, -1, deadline.Token);
            int offset = 0;
            if (PacketIO.ReadVarInt(response, ref offset) != 0) { remote.Dispose(); return null; }
            _ = PacketIO.ReadString(response, ref offset);
            PacketIO.RequireEnd(response, offset);
            return new StatusConnection(remote, response);
        }
        catch (Exception ex) when (ex is IOException or SocketException or InvalidDataException or OperationCanceledException)
        {
            remote.Dispose();
            if (lifetime.IsCancellationRequested) throw;
            return null;
        }
    }
}