# Cryptographic design and analysis

This document describes Token Vault's security goals, the adversaries it considers, every cryptographic
mechanism it uses, why each one was chosen, and where the guarantees stop. It also analyses the Minecraft
Java Edition login protocol. Token Vault has to interoperate with that protocol unchanged, so several of
its primitives are fixed by Mojang rather than chosen here.

Source references point at files in this repository. Section 12 maps every claim that a test can check
to that test. Claims that rest on Windows behaviour (AppContainer, DPAPI, the TPM) are marked as such; the
regression suite cannot check them and they are listed in `docs/ACCEPTANCE.md`.

---

## 1. Problem

Minecraft Java Edition authenticates a player to a server with a **bearer token**: a Minecraft access
token, valid for about 24 hours, obtained through Microsoft → Xbox Live → XSTS → Minecraft services.
The game client (the JVM) normally holds this token in memory and passes it on its command line. Every
mod runs in the same JVM with the same rights, so any mod can read the token and send it off the
machine. A stolen token gives full use of the account until it expires: joining servers, chat, and
changing name or skin. Many stealers also take the long-lived Microsoft refresh token from launcher files,
and with that the account indefinitely.

**Goal:** let the player run untrusted mods while the game still plays online normally, such that no code
inside the game can obtain a **credential** (access token, refresh token) or a **sign-in for a connection
of its choosing**. Section 2 states exactly what that does and does not cover.

## 2. System and adversary model

**Principals**

| Principal | Trust | Holds |
|---|---|---|
| Vault (`TokenVault.exe`), normal integrity, the user's account | Trusted | Microsoft refresh token, Minecraft access token, session secrets |
| Game: JVM + loader + **every mod**, in a Windows AppContainer at Low integrity | **Adversarial** | A fake token; the decrypted stream of any connection the player approved; the chat-signing key pair (§4.6) |
| Minecraft server the player added | Untrusted for the account (it learns the username and UUID, as with any client) | Its own RSA key pair |
| Microsoft / Xbox / Mojang services | Trusted third party | — |
| GitHub (release hosting) | Untrusted for code: updates are verified against a key it never holds (§9) | Release files |

**Adversaries**

* **A_mod**: arbitrary code in the game process. It can read and write the game's memory, open network
  connections (outbound internet, loopback), read and write the folders granted to the sandbox, draw
  anything in the game window, choose *when* the game opens a connection, and call the vault's local
  HTTPS API and brokers with any input. This is the primary adversary.
* **A_srv**: a server on the player's list that is malicious. It sees what any server sees and can
  forward bytes anywhere.
* **A_net**: a network attacker between the vault and a server, or between the vault and GitHub. It can
  drop, reorder, inject or modify traffic, and may run its own server.
* **A_local**: another program or another Windows user on the same PC that is *not* in the game sandbox
  and does not run as this user with full rights (for example a second account on a family PC). It can
  connect to loopback ports.
* **A_offline**: holds a copy of the vault's files: a stolen disk, an image or a backup.
* **Out of scope**: unsandboxed malware running as the same Windows user or as administrator, kernel
  compromise, and AppContainer escapes (Windows vulnerabilities). They can read the vault's memory
  directly. No user-mode design defends against that (§11).

**Security goals**

* **G1 (credential confinement):** A_mod and A_local learn neither the Minecraft access token nor the
  Microsoft refresh token.
* **G2 (no authentication oracle):** the vault calls Mojang's `join` only for a connection that (a) the
  vault itself opened, (b) to the address of a server on the player's list, (c) whose shared secret the
  vault generated and never revealed, and (d) that was requested by the game's own process and, unless
  the player turned approval off, approved by the player in the vault's window.
* **G3 (at-rest protection):** without this Windows user's DPAPI keys, A_offline learns nothing about the
  refresh token beyond the file's length and which key-wrapping method was used. With the TPM method,
  this also holds for an A_offline who knows the user's password, as long as they don't have this PC's
  TPM. Any change to the stored file is detected.
* **G4 (local channel authenticity):** the game talks only to the genuine vault API, and only a holder of
  the session's fake token can use the API's authenticated routes (two routes are public; §5).
* **G5 (download and update integrity):** game files, libraries, loaders and Token Vault updates match
  hashes published by their publisher; for updates, a signature by Token Vault's release key (§8, §9).

**What G1–G2 deliberately do not cover.** Once the player approves a join, A_mod holds the *decrypted*
game stream of that connection: it can play as the player there, and it can forward that stream to
another machine, so a remote attacker plays in the player's place for as long as the connection lasts.
Actions it takes there (trades, chat, server-side account linking, getting banned) can outlast the
connection. A_mod can also use the chat-signing key for its validity period (§4.6). G2 limits *which*
connections get signed in, and the vault gives the player a way to end one (Disconnect); it cannot make
an approved connection safe from the code that the player chose to run.

## 3. Architecture: confinement plus a channel-bound login broker

```
 Vault (trusted)                                        Game sandbox (A_mod)
 ─────────────────────────────────                      ─────────────────────────
 refresh token ── TPM+DPAPI envelope (§7)
 access token ─┬─ HTTPS API, 127.0.0.1, TLS (§5) ◄────── fake token (random, useless upstream)
               │    fixed allowlist, token swapped in
               └─ Login broker (§4) ◄───────────────────  plain local Minecraft connection
                    accepts only the game's processes      (game job membership checked)
                    owns the RSA/AES handshake with the server
                    calls Mojang "join" itself
                    relays the encrypted session
```

* The JVM is started with a **fake token**: a JWT-shaped string with 512 bits of randomness
  (`Core/FakeToken.cs`). Mojang rejects it, so on its own it is worthless.
* Authlib's service hosts are redirected (JVM system properties) to the vault's loopback HTTPS API
  (`Vault/HttpsVault.cs`). A fixed list of five routes is forwarded with the real token swapped in
  (`docs/ALLOWLIST.md`); every `join` alias, name or skin change, and any other path gets 403. The vault
  rebuilds each upstream request itself and forwards no caller-chosen URL, host, header, query string or
  body. A response that contains the real token is suppressed.
* **The game never performs the server-side authentication step.** It connects to a vault-owned
  **broker** on loopback, one per server the player added (§4). A broker serves a connection only if the
  process at the other end belongs to the game's job object (`Launcher/LoopbackPeers.cs`,
  `SandboxedProcess.Contains`): loopback is shared by every program and every Windows user on the PC.
* The AppContainer stops A_mod from reading the vault's memory or its files. That isolation is enforced
  by Windows, not by cryptography. Without it, G1 cannot hold.

**Argument for G1.** The real tokens exist only in vault memory, the vault's private data folder (§7)
and TLS connections from the vault to Microsoft and Mojang. None of these is readable by the sandbox:
OS access control covers memory and the folder (Windows behaviour, not checked by the test suite), and
the vault, not the JVM, holds the TLS keys. The vault's outputs to the sandbox are API responses and
relayed game traffic. API responses contain no token (checked by a canary test, plus a byte-level search
for the token's exact bytes before any response is sent). Relayed traffic is the server's own stream,
decrypted by the vault, and holds no vault credential. A_local can reach the same loopback ports but has
no fake token and is refused by the brokers' origin check.

## 4. The Minecraft login and why the broker exists

### 4.1 The protocol (online mode)

```
C → S  Handshake(host, port, next=login); Login Start(name, uuid)
S → C  Encryption Request(serverId, pk_S [X.509 SubjectPublicKeyInfo, RSA-1024], verifyToken)
C      s ←$ {0,1}^128                                        (shared secret)
C      h = SHA-1(serverId ‖ s ‖ pk_S), printed as a signed two's-complement big-endian hex number
C → Mojang  join(accessToken, uuid, h)                        (HTTPS)
C → S  Encryption Response(RSA-PKCS#1v1.5_pk_S(s), RSA-PKCS#1v1.5_pk_S(verifyToken))
S      decrypts s; S → Mojang hasJoined(name, h') with h' recomputed from its view
S, C   switch both directions to AES-128-CFB8 with key = IV = s
```

`h` is implemented in `Core/MinecraftCrypto.cs` (`ServerHash`). It is checked against the known-answer
vectors "Notch" → `4ed1f46b…` and "jeb_" → `-7c9d5b00…` (`CryptoTests`).

### 4.2 `join` is an authorization oracle

A successful `join(token, uuid, h)` means: *"the holder of this account authorizes the one connection
whose transcript hash is h"*. The server checks only `hasJoined(name, h')`. So whoever can cause a
`join` for a chosen `h` can log in as the player **to any server, from any machine**:

1. The attacker connects to target server T from its own machine, as the victim's username.
2. It receives `(serverId, pk_T)`, picks its own `s*`, and computes `h* = SHA-1(serverId ‖ s* ‖ pk_T)`.
3. It gets a `join` for `h*` done in the victim's name. T's `hasJoined` succeeds, and the attacker
   plays as the victim, with keys only the attacker knows.

So hiding the bearer token is **not enough**: a vault that offered a "please join h" API to the game
would be a confused deputy that leaks the account's power without leaking the token. That is why the API
refuses every `join` route unconditionally (`VaultPolicy`, `HttpTests`).

### 4.3 The broker: the vault authenticates only connections whose secret it chose

`Vault/ConnectionBroker.cs` performs the client side of §4.1 itself:

* It serves a loopback connection only if the connecting process is in the game's job (G2 d). Until the
  game is running, and whenever the check can't be made, nothing is served.
* It connects to the address of a server the player configured in Token Vault, never to one the game
  names (the address in the game's handshake is ignored) (G2 b).
* It draws `s` itself from the OS CSPRNG, computes `h` over **its own** `s`, calls `join`, encrypts `s`
  to the key the server sent, and keeps `s` and the AES state inside the vault. The game receives the
  decrypted stream only after login. It never sees `serverId`, `pk_S`, `s` or `h` (G2 a, c).
* By default the player approves each join in a window the sandbox cannot click or type into (UIPI). The
  sandbox *can* choose when that window appears, so the Join button only works after the window has been
  shown and active for 1.2 s, and the window's position and button order are randomised: a click the
  player was about to make on something the game drew does not land on Join (`App/JoinPrompt`).
* One authenticated connection can exist at a time across all servers, and sign-ins are limited to one
  every 3 s across all servers (`BrokerGate`). The vault shows the live connection with a Disconnect
  button.
* After the session's sign-in deadline (§5) no new `join` is made; a connection already playing is kept.

**Argument for G2 (a, c).** For the vault to authorize a connection whose secret A_mod knows, the
transcript hash of that connection must equal an `h` the vault sends to `join`. Each such `h` contains a
fresh 128-bit `s` that A_mod never sees. Matching it means one of three things:
(i) guessing `s` (probability 2⁻¹²⁸ per attempt);
(ii) finding a SHA-1 *second preimage* for a hash whose input contains 128 bits the attacker doesn't
choose. Known SHA-1 attacks are collisions, including chosen-prefix collisions (Leurent–Peyrin 2020).
Those need the attacker to control both colliding inputs, which it does not here, so this would need a
generic second-preimage attack (≈2¹⁶⁰ work);
(iii) learning `s` from the vault: excluded by the isolation in §3.
This argument is informal; §11 lists a symbolic model as future work.

**What G2 does not give.** (1) The vault cannot know *which machine* answers at a listed address. A
malicious listed server A_srv can forward the login to another server T, passing T's `(serverId, pk_T)`
through. The vault then signs the player in to **T**, which the player never chose. A_srv cannot decrypt
`s` (it is encrypted to `pk_T`), so on its own it is only a blind relay, exactly as for the vanilla client.
But combined with A_mod, which receives T's decrypted stream, the pair can use the player's sign-in on
any server. Pinning server keys would not help: servers generate a new key pair on every start. G2
therefore assumes the servers on the list are honest about where they forward. (2) As stated in §2, the
game holds every approved connection.

### 4.4 Weaknesses of the fixed protocol (not fixable client-side)

Token Vault must speak this protocol unchanged, or no server would accept it. These are inherited from
Mojang's design:

| Issue | Consequence | Assessment |
|---|---|---|
| RSA-1024 server keys | ≈80-bit security (NIST SP 800-57 no longer approves it) | A party that can factor `pk_S` and records the login learns `s`, can decrypt that session and, being on path, can inject into it: a session takeover for that connection. It still cannot obtain a `join` for a connection of its own (no token), so G1 holds; for that connection, G2's "secret never revealed" does not |
| RSA PKCS#1 v1.5 encryption | Bleichenbacher padding-oracle attacks on the server | A server-side issue. The client only encrypts |
| AES-CFB8 with key = IV, same key both ways | Both directions start from the same register, so while the two plaintexts agree byte for byte, the ciphertexts are identical, and at the first difference c ⊕ c′ = p ⊕ p′ | Leaks whether the two directions' first bytes match and the XOR at the first differing byte; packet lengths come first, so little of value |
| No MAC on the stream | CFB8 is malleable: flipping bit *j* of ciphertext byte *i* flips the same bit of plaintext byte *i* and garbles the next 16 bytes | An on-path attacker can tamper predictably with one byte per flip. Integrity rests on the parser rejecting garbage |
| SHA-1 transcript hash | Collision-weak | Not exploitable as used. The hash input contains a secret the attacker doesn't control (§4.3 ii) |

The broker uses fresh CSPRNG secrets, checks the server key (`RSA.ImportSubjectPublicKeyInfo` must consume
the whole key, at least 1024 bits), and refuses offline-mode servers. Offline mode would skip `join`
entirely and offer no protection, so the broker fails closed (`OfflineTests`).

### 4.5 Implementation notes

* .NET's CFB mode can buffer a whole block on some platforms. The game needs per-byte progress, so
  `Cfb8Transform` builds CFB8 from AES-ECB with an explicit shift register. Decryption is batched: every
  register state is made of ciphertext bytes that are already known, so one AES-ECB call produces the
  keystream for a whole chunk (80–130 MiB/s on one core in a Linux measurement, against 4.5 MiB/s byte by
  byte; not measured on Windows). Encryption
  stays sequential. A vector generated independently with OpenSSL, and a byte-by-byte reference over
  random data and random chunking, check both directions (`CryptoTests`, `Cfb8BatchTests`).
* `s` is zeroed after use. The RSA key and AES transforms are disposed when the connection ends.
* Version differences in the login packets are handled exactly (1.19 "has verify token" flag, 1.20.2
  login acknowledgement, 1.20.5 `shouldAuthenticate` flag), and the server's reported UUID and name must
  match the signed-in account.
* **Difference from the vanilla client:** on 1.19–1.19.2 (protocols 759/760) the vanilla client answers
  the encryption request with a signature by its chat key instead of the encrypted verify token when it
  has a key. The broker always sends the verify token, which servers accept but which distinguishes it.
  On all other versions the packets are the game's own or the vanilla ones.
* Server transfers (1.20.5+) and Realms are not supported: both need a `join` the vault does not make.

### 4.6 Chat-signing keys (1.19+)

From 1.19 the client signs chat with a profile key pair issued by `/player/certificates`. The game needs
the private key to chat, so by default the vault serves it. A_mod can therefore copy the key and sign
chat as the player **until the key expires (about two days), also after the session**: on servers it
controls, and in material it could submit to Mojang's player-reporting system. The key cannot log in,
cannot `join` and cannot change the account, and Mojang can revoke it. The player can turn signed chat
off (`AllowChatSigning`); then the route is refused and servers that require signed chat (vanilla's
default `enforce-secure-profile`) won't accept the player.

## 5. The local API channel (G4)

* **Server authentication.** The vault creates a new self-signed certificate for each session
  (RSA-2048, SHA-256, SAN `IP:127.0.0.1`, EKU serverAuth, valid one day) in `Vault/LocalCertificate.cs`.
  The game trusts it through a per-launch JKS truststore (`Launcher/JavaTrustStore.cs`). The vault binds
  its port before the game starts, and another process squatting on the port first can't present a
  certificate the game accepts. The truststore also holds the Windows roots so that ordinary HTTPS from
  mods (skins, resource packs) still works. Public CAs do not issue certificates for `127.0.0.1`.
* **Protocol versions.** TLS 1.2 and 1.3 only (`HttpsConnectionAdapterOptions.SslProtocols`).
* **Client authentication.** Requests to the three authenticated routes carry the fake token as a bearer
  credential. The vault compares `SHA-256(supplied)` with `SHA-256(expected)` using
  `CryptographicOperations.FixedTimeEquals`; hashing first gives a fixed-length comparison that doesn't
  leak the expected length or a prefix. The token has 512 random bits: a 256-bit `jti` plus a 256-bit
  filler "signature". Only an online, loopback-only guessing attack is possible; all requests, including
  those with a wrong token, count toward a limit of 120 per minute (`ApiHardeningTests`). The public-key
  list and public profile lookups need no token, exactly as at Mojang.
* **Why the fake token is useless if stolen.** It is accepted only by the vault, only from loopback and
  only for the allowlisted routes, and it stops working at the session deadline (the earlier of
  `SessionMinutes` and the access token's expiry). Sent to Mojang, it gets 403 (checked once against the
  real endpoint; `VALIDATION.md`).

## 6. Microsoft sign-in

`Vault/OAuthLogin.cs` and `Vault/SystemBrowserUi.cs` use MSAL with:

* the **authorization-code flow with PKCE** (RFC 7636, `S256`). The adapter refuses any authorization
  URL without an `S256` challenge of at least 43 characters, or with a state shorter than 16 characters.
* a **loopback redirect** to the literal `127.0.0.1` on a fixed port (RFC 8252 §7.3), not `localhost`,
  so name resolution can't redirect it.
* **state validation** by comparing SHA-256 digests in constant time. Wrong state, wrong path or a
  non-loopback peer is refused (`OAuthCallbackTests`).
* sign-in only while no game is running, so no mod is alive during the flow.
* an optional device-code flow. The vault shows only the user code and Microsoft's verification page,
  and checks that page's host against Microsoft's domains.

## 7. Data at rest (G3)

The only persistent secret is MSAL's cache, and it is **filtered** first: access and ID tokens are
removed and only the refresh token, account and app metadata are kept. Unknown cache sections are
refused (`RefreshCacheFilter`, tested against MSAL's real serialization).

### 7.1 Envelope format (`Core/Envelope.cs`, v2)

```
"TVE1" ‖ 0x02 ‖ wrapId ‖ len(W) [u16 BE] ‖ W ‖ nonce [12] ‖ C ‖ tag [16]

DEK ←$ {0,1}^256                      fresh for every write
W   = Wrap_wrapId(DEK)
C‖tag = AES-256-GCM(DEK, nonce, plaintext,
          AD = header ‖ len(ctx) [u32 BE] ‖ ctx)
ctx = "TokenVault.RefreshCache.v2|" ‖ <Windows user SID>
```

* **Confidentiality and integrity.** AES-GCM is an AEAD (IND-CPA and INT-CTXT, hence IND-CCA, under a
  uniformly random key with unique nonces; NIST SP 800-38D). Each DEK encrypts exactly **one** message,
  so nonce reuse under a key can't happen, whatever the random nonce turns out to be. The security of the
  whole envelope reduces to that of the key wrap (§7.2): an adversary who can unwrap `W` reads the file.
  The envelope reveals the plaintext length and `wrapId`.
* **Binding.** The whole header (magic, version, wrap method, wrapped key) and the context are
  authenticated data. Changing any of them, or moving a file to another purpose or Windows user, makes
  decryption fail instead of producing different plaintext. The context is length-prefixed, so AD
  encodings can't be ambiguous. A test flips every byte of an envelope in turn and checks that each one is
  rejected (`EnvelopeTests`).

### 7.2 Key wrapping (`Vault/WindowsKeyWrap.cs`)

| wrapId | Wrap(DEK) | Opens only with |
|---|---|---|
| 1 | DPAPI-CurrentUser(DEK, entropy) | this Windows user's DPAPI master keys |
| 2 | DPAPI-CurrentUser(RSA-OAEP-SHA256_TPM(DEK)) | this user's DPAPI keys **and** this physical TPM |

For wrapId 2 the RSA-2048 key is created in the **Microsoft Platform Crypto Provider** (the TPM 2.0)
with export policy *none*: the private key is held under the TPM's storage key and never exists outside
it. The vault picks wrapId 2 only after a full wrap/unwrap round trip succeeds; otherwise it falls back to
wrapId 1. (Windows behaviour; the TPM path has not been exercised by the automated tests, see
`VALIDATION.md`.)

**Against A_offline.** DPAPI master keys are protected by the user's logon secret, so a disk image plus
the password (or an offline guess of it, or a domain backup key) opens a **wrapId 1** file: with the DPAPI
fallback, a copied file is *not* useless elsewhere. A wrapId 2 file additionally needs the TPM-resident
private key, which can't be exported, so a copy is useless off the device.

**Sign-out.** Signing out deletes the file and the TPM key. For wrapId 2 this is crypto-shredding: no copy
of an earlier file can be opened afterwards, even on the same PC. For wrapId 1 there is nothing to shred;
a copy stays as strong as the user's password. In both cases **the refresh token stays valid at
Microsoft** until it expires or the user revokes the app's access at Microsoft
(account.live.com/consent/Manage); Microsoft offers no per-token revocation endpoint for public clients.

**Compatibility and failure.** v1 files (raw DPAPI, before this format) are still read and rewritten as
v2 on the next save. A file that fails authentication, belongs to another PC or user, or whose TPM key is
gone is treated as "not signed in": it is deleted and the user signs in again. A file is never partly
trusted. If the TPM key still exists but the TPM does not answer (busy, lockout), the file is **kept** and
the user is asked to retry, so a passing TPM problem doesn't cost the saved sign-in.

**What it does not stop:** malicious code running *as the same user, on the same PC, unsandboxed* can ask
DPAPI and the TPM to unwrap, just as the vault does. Stopping that would need a user-presence gesture for
every use of the key (for example Windows Hello), which is listed as future work (§11).

## 8. Download integrity (G5)

* Game files come only from a fixed set of HTTPS hosts. Each Mojang file is checked against the SHA-1 in
  Mojang's manifests (fetched over TLS). Mojang publishes no stronger hash. Replacing a file undetected
  would need a SHA-1 **second preimage** of Mojang's file; collision attacks don't apply because the
  attacker doesn't control Mojang's file.
* Fabric and Quilt libraries are checked against the SHA-1 in the loader's profile, or, where a profile
  entry carries none, against the `.sha1` file the Maven repository publishes. The Forge/NeoForge
  installer is checked against its Maven `.sha1`. With no published hash, nothing is installed. These
  hashes travel over the same TLS as the files, so they protect against corruption and mirror mix-ups,
  not against a compromised repository.
* The Forge/NeoForge installer runs inside the sandbox and fetches its own files; what it verifies is up
  to it. After it finishes, its folder becomes read-only to the sandbox, because every instance on that
  loader version shares it.
* Modrinth packs are checked against the pack's SHA-512 (or SHA-1). CurseForge publishes no hashes
  without an API key, so CurseForge downloads are checked only by TLS. Non-HTTPS downloads are refused.
* Archives are extracted with checks against path traversal, links, and size: 2 GiB per file and 16 GiB
  of bytes actually written per import, whatever the archive claims (`PackTests`, `PackImportTests`).
  From a player's own game folder (a zipped `.minecraft`, a Prism/MultiMC export) only mods, settings,
  packs and worlds are copied, and files that look like sign-in data (other launchers' and clients'
  account files) are never copied from any pack.
* Integrity isn't trust: a correctly downloaded mod can still be malicious. That is exactly why the game
  runs confined (§3).

## 9. Software updates

`Vault/Updater.cs` checks the GitHub Releases of the configured repository at start-up and every six
hours (if the player leaves it on).

* **What is trusted.** A release is installed only if `TokenVault-update.json` — product, version, file
  name, SHA-256 and size of the package — carries a valid ECDSA P-256 / SHA-256 signature by the release
  key whose **public** half is built into the running program. The private key exists only as a CI secret
  and is used in the release job; the job verifies its own signature before publishing.
* **Against A_net and a compromised GitHub account or release.** Without the private key, a changed
  package fails the SHA-256 check and a changed manifest fails the signature (`UpdaterTests`). Downloads
  are HTTPS only and may only come from GitHub hosts.
* **Rollback.** The signed manifest names its version, which must equal the release tag and be newer than
  the running build, so an old (validly signed, possibly vulnerable) release can't be replayed.
* **Freeze.** An attacker who can block or hide releases can keep a player on an old version; the updater
  can't detect that. Players still see a newer release on GitHub.
* **Installation.** The new program is unpacked into a private folder and swapped in by renaming the
  running file (Windows allows renaming, not overwriting, a running `.exe`). It takes effect at the next
  start. Nothing runs before the signature and hash checks pass.
* **Key compromise.** Whoever holds the private key can push code to every installed copy. The key must be
  kept out of the repository; rotating it requires players to download one release by hand.
* A build without a public key never installs anything; it only tells the player a release exists.

## 10. Usage statistics

`Vault/Telemetry.cs` sends anonymous usage events to PostHog **only after the player opts in** (asked
once; off until answered) and only when the build carries a PostHog *project* key. The set of events and
properties is fixed in code and checked on every send: app and Windows version, Minecraft version and
loader of a launch, whether launches and joins succeeded, and a random per-install identifier.
It never contains the account name or UUID, Microsoft data, server addresses, file paths, mod names,
or anything from the game; GeoIP lookup is disabled per event and person profiles are not created
(`TelemetryTests`). PostHog still receives the IP address of each request; the project should enable
"Discard client IP data".

## 11. Side issues, non-goals and limitations

* **Managed-memory hygiene.** Secret byte arrays are zeroed (`CryptographicOperations.ZeroMemory`), but
  strings created by MSAL, JSON and HTTP can't be reliably erased in .NET. The vault never writes real
  tokens to logs, command lines, environment variables or files other than the envelope.
* **Logs** record classified events only: never headers, bodies, tokens or join hashes.
* **Same-user unsandboxed malware, administrators, kernel and AppContainer escapes** are out of scope.
* **The sandbox is a standard AppContainer, not a less-privileged one (LPAC)**, so it can read what Windows
  grants to all app packages (system folders, parts of the registry). It shares the player's desktop:
  whether it can capture the screen or observe other windows' input on a given Windows build has not been
  tested. Clipboard access is blocked by default.
* **In-game abuse and session handover** (§2) and **chat-key misuse** (§4.6) are inherent.

Future work:

1. **Formal model.** Model the broker handshake and the vault API in a symbolic protocol verifier
   (ProVerif or Tamarin), with A_mod as a compromised client role, and prove G2 (a, c) under Dolev–Yao
   assumptions.
2. **User-presence-gated key.** Require a Windows Hello gesture to unwrap the TPM key
   (`NCRYPT_UI_POLICY`), extending G3 to same-user malware at the cost of a prompt each launch.
3. **Tamper-evident audit log.** Forward-secure MAC chaining (Bellare–Yee) of join and denial events.
4. **Stronger sandbox.** LPAC and a separate desktop for the game, if Java and the graphics stack allow it.
5. **Protocol.** The stream's lack of integrity and its 1024-bit RSA can only be fixed by Mojang, for
   example with an AEAD and an ephemeral key exchange in the login.
6. **Independent review.** This design has not been audited by a third party.

## 12. Verification

`dotnet run --project tests/TokenVault.Tests -c Release` (runs in CI on Windows and Linux). All network
peers in these tests are local mocks; none involve Microsoft, Mojang, a real server or a TPM.

| Property | Test group |
|---|---|
| SHA-1 transcript hash known answers, positive and negative | `CryptoTests` |
| AES-CFB8 matches an independent OpenSSL vector and a byte-by-byte reference over random data and chunking | `CryptoTests`, `Cfb8BatchTests` |
| Fake tokens unique and well-formed; only refresh tokens persisted | `TokenTests` |
| Envelope round trip; fresh DEK per seal; every-byte tamper rejection; context and key-wrap binding; truncation | `EnvelopeTests` |
| DPAPI envelope round trip (Windows); TPM-bound round trip where a TPM key exists | `EnvelopeTests` |
| PKCE required; wrong OAuth state refused | `OAuthCallbackTests` |
| TLS API: all join aliases denied, wrong fake denied, token substituted, real token never returned | `HttpTests` |
| Wrong-token guesses rate-limited; chat-signing key refused when signed chat is off | `ApiHardeningTests` |
| Broker: mock server decrypts the broker's RSA-wrapped secret and checks the matching join hash; game never sees the encryption request; encrypted relay of 100 KB each way | `BrokerTests` |
| Broker refuses non-game connections; no sign-in after the deadline; reconnect limit shared by all servers; Disconnect ends the live connection | `BrokerHardeningTests` |
| Offline-mode server refused before any authentication; game told why | `OfflineTests` |
| Join approval and the single-connection invariant | `ApprovalTests` |
| Pack import: only game content from game folders, no credential files, real byte cap, pack version and loader applied | `PackTests`, `PackImportTests` |
| Updates: signed manifest accepted; altered package, foreign signature, older version and non-GitHub redirect refused; in-place swap | `UpdaterTests` |
| Statistics: fixed events and properties, no personal keys, HTTPS only | `TelemetryTests` |

What remains manual (real account, real TPM, real servers, Windows isolation) is listed in
`docs/ACCEPTANCE.md`.

## References

* NIST SP 800-38D (GCM); SP 800-57 Part 1 Rev. 5 (key sizes); FIPS 186-5 (ECDSA).
* RFC 7636 (PKCE); RFC 8252 (OAuth 2.0 for native apps); RFC 8446 (TLS 1.3); RFC 8017 (PKCS #1 v2.2, OAEP).
* D. Bleichenbacher, "Chosen ciphertext attacks against protocols based on the RSA encryption standard
  PKCS #1", CRYPTO 1998.
* G. Leurent, T. Peyrin, "SHA-1 is a Shambles", USENIX Security 2020.
* M. Bellare, B. Yee, "Forward-security in private-key cryptography", CT-RSA 2003.
* J. Samuel, N. Mathewson, J. Cappos, R. Dingledine, "Survivable key compromise in software update
  systems" (The Update Framework), CCS 2010.
* Microsoft: AppContainer isolation; DPAPI (`CryptProtectData`); Platform Crypto Provider (TPM key storage).
* wiki.vg / minecraft.wiki, "Protocol encryption" (Minecraft login).
