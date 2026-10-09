# Cryptographic design and analysis

This document describes Token Vault's security goals, the adversaries it considers, every cryptographic
mechanism it uses, why each one was chosen, and where the guarantees stop. It also analyses the Minecraft
Java Edition login protocol. Token Vault has to interoperate with that protocol unchanged, so several of
its primitives are fixed by Mojang rather than chosen here.

Source references point at files in this repository. Section 10 maps every claim that a test can check
to that test.

---

## 1. Problem

Minecraft Java Edition authenticates a player to a server with a **bearer token**: a Minecraft access
token, valid for about 24 hours, obtained through Microsoft → Xbox Live → XSTS → Minecraft services.
The game client (the JVM) normally holds this token in memory and passes it on its command line. Every
mod runs in the same JVM with the same rights, so any mod can read the token and send it off the
machine. A stolen token gives full use of the account until it expires: joining servers, chat, and
changing name or skin. With it, many mods also steal the long-lived Microsoft refresh token, and with
that the account indefinitely.

**Goal:** let the player run untrusted mods while the game still plays online normally, such that **no
code inside the game can obtain any credential that is useful outside the game session it is running
in.**

## 2. System and adversary model

**Principals**

| Principal | Trust | Holds |
|---|---|---|
| Vault (`TokenVault.exe`), normal integrity, the user's account | Trusted | Microsoft refresh token, Minecraft access token, session secrets |
| Game: JVM + loader + **every mod**, in a Windows AppContainer at Low integrity | **Adversarial** | A fake token; the chat-signing key pair (§5.5) |
| Minecraft server | Untrusted for the account (it learns the username and UUID, as with any client) | Its own RSA key pair |
| Microsoft / Xbox / Mojang services | Trusted third party | — |

**Adversaries**

* **A_mod**: arbitrary code in the game process. It can read and write the game's memory, open network
  connections (outbound internet, loopback), read and write the folders granted to the sandbox, and
  call the vault's local HTTPS API and brokers with any input. This is the primary adversary.
* **A_net**: a network attacker between the vault and a server. It can drop, reorder, inject or modify
  traffic, and may run its own server.
* **A_offline**: holds a copy of the vault's files: a stolen disk, an image or a backup.
* **Out of scope**: unsandboxed malware running as the same Windows user or as administrator, and kernel
  compromise. They can read the vault's memory directly. No user-mode design defends against that
  (§9).

**Security goals**

* **G1 (credential confinement):** A_mod learns neither the Minecraft access token nor the Microsoft
  refresh token.
* **G2 (no authentication oracle):** A_mod cannot get the account authenticated to a server connection
  it controls, or to a server the player did not choose and approve.
* **G3 (at-rest protection):** A_offline learns nothing about the refresh token. Any change to the
  stored file is detected.
* **G4 (local channel authenticity):** the game talks only to the genuine vault API, and only a holder
  of the session's fake token can use that API.
* **G5 (download integrity):** game files, libraries and mods match their publishers' published hashes.

## 3. Architecture: confinement plus a channel-bound login broker

```
 Vault (trusted)                                        Game sandbox (A_mod)
 ─────────────────────────────────                      ─────────────────────────
 refresh token ── TPM+DPAPI envelope (§7)
 access token ─┬─ HTTPS API, 127.0.0.1, TLS (§6) ◄────── fake token (random, useless upstream)
               │    fixed allowlist, token swapped in
               └─ Login broker (§4) ◄───────────────────  plain local Minecraft connection
                    owns the RSA/AES handshake with the server
                    calls Mojang "join" itself
                    relays the encrypted session
```

* The JVM is started with a **fake token**: a JWT-shaped string with 512 bits of randomness
  (`Core/FakeToken.cs`). Mojang rejects it, so on its own it is worthless.
* Authlib's service hosts are redirected (JVM system properties) to the vault's loopback HTTPS API
  (`Vault/HttpsVault.cs`). Only three fixed read-only routes are forwarded, with the real token swapped
  in. Every `join` alias, name or skin change, and any other path gets 403 (`docs/ALLOWLIST.md`). The
  vault rebuilds each upstream request itself. It forwards no caller-chosen URL, host, header, query
  string or body. A response that contains the real token is suppressed.
* **The game never performs the server-side authentication step.** It connects to a vault-owned
  **broker** on loopback, one per server the player added (§4).
* The AppContainer stops A_mod from reading the vault's memory or its files. That isolation is enforced
  by Windows, not by cryptography. Without it, G1 cannot hold.

**Argument for G1.** The real tokens exist only in vault memory, the vault's private data folder (§7)
and TLS connections from the vault to Microsoft and Mojang. None of these is readable by the sandbox:
OS access control covers memory and the folder, and the vault, not the JVM, holds the TLS keys. The
vault's outputs to the sandbox are API responses and relayed game traffic. API responses contain no
token (checked by a canary test, plus a byte-level search before any response is sent). Relayed
traffic is the server's own encrypted stream, decrypted by the vault and holding no vault credential.

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

So simply hiding the bearer token is **not enough**: a vault that offered a "please join h" API to the
game would be a confused deputy that leaks the account's power without leaking the token. That is why
the API refuses every `join` route unconditionally (`VaultPolicy`, `HttpTests`).

### 4.3 The broker: the vault authenticates only connections whose secret it chose

`Vault/ConnectionBroker.cs` performs the client side of §4.1 itself:

* It connects to a server the player configured in Token Vault, never to one the game names (the
  address in the game's handshake is ignored).
* It draws `s` itself from the OS CSPRNG, computes `h` over **its own** `s`, calls `join`, encrypts `s`
  to the server's key, and keeps `s` and the AES state inside the vault. The game receives the
  decrypted stream only after login. It never sees `serverId`, `pk_S`, `s` or `h`.
* By default the player approves each join in a window the sandbox cannot drive (UIPI). Only one
  authenticated connection can exist at a time, and reconnects are rate-limited.

**Argument for G2.** For A_mod to make the vault authorize a connection it controls, the transcript
hash of that connection must equal an `h` the vault sends to `join`. Each such `h` contains a fresh
128-bit `s` that A_mod never sees. Matching it means one of three things:
(a) guessing `s` (probability 2⁻¹²⁸ per attempt);
(b) finding a SHA-1 *second preimage* for a hash whose input contains 128 bits the attacker doesn't
choose. Known SHA-1 attacks are collisions, including chosen-prefix collisions (Leurent–Peyrin 2020).
Those need the attacker to control both colliding inputs, which it does not here, so this would need a
generic second-preimage attack (≈2¹⁶⁰ work);
(c) learning `s` from the vault: excluded by the isolation in §3.
A_mod can still choose *which* configured server to connect to. Approval and the one-connection rule
limit that to servers the player picked, at the moment the player picked them.

**Relay by a malicious server (A_net).** A server S on the player's list could forward the login to
another server T, passing T's `(serverId, pk_T)` through. The vault then authorizes a connection to T,
but encrypts `s` to `pk_T`. S cannot decrypt it (RSA), so S becomes a blind relay of ciphertext it
can't read. This is the protocol's intended man-in-the-middle resistance. The broker keeps it by
generating `s` itself, exactly as the vanilla client would.

### 4.4 Weaknesses of the fixed protocol (not fixable client-side)

Token Vault must speak this protocol unchanged, or no server would accept it. A rigorous analysis still
has to name its weaknesses:

| Issue | Consequence | Assessment |
|---|---|---|
| RSA-1024 server keys | ≈80-bit security (NIST SP 800-57 withdrew it) | A party able to factor `pk_S` and record traffic can recover `s` and decrypt that session. It still cannot forge `join` (no token), so G1/G2 are unaffected |
| RSA PKCS#1 v1.5 encryption | Bleichenbacher padding-oracle attacks on the server | A server-side issue. The client only encrypts |
| AES-CFB8 with IV = key | Deterministic start: both directions begin from the same register `E_K(IV)`, so the first ciphertext bytes satisfy c₀ᴬ ⊕ c₀ᴮ = p₀ᴬ ⊕ p₀ᴮ | Leaks the XOR of the first bytes (packet-length VarInts) |
| No MAC on the stream | CFB8 is malleable: flipping bit *j* of ciphertext byte *i* flips the same bit of plaintext byte *i* and garbles the next 16 bytes | An on-path attacker can tamper predictably with one byte per flip. Integrity rests on the parser rejecting garbage |
| SHA-1 transcript hash | Collision-weak | Not exploitable as used. The hash input contains a secret the attacker doesn't control (§4.3 b) |

These are inherited from Mojang's design. The broker uses fresh CSPRNG secrets, checks the server key
(`RSA.ImportSubjectPublicKeyInfo` must consume the whole key, at least 1024 bits), and refuses
offline-mode servers. Offline mode would skip `join` entirely and offer no protection, so the broker
fails closed (`OfflineTests`).

### 4.5 Implementation notes

* .NET's CFB mode can buffer a whole block on some platforms. The game needs per-byte progress, so
  `Cfb8Transform` builds CFB8 from AES-ECB with an explicit shift register. A vector generated
  independently with OpenSSL, fed in unaligned chunks, checks that encryption and decryption stay
  continuous (`CryptoTests`).
* `s` is zeroed after use. The RSA key and AES transforms are disposed when the connection ends.
* Version differences in the login packets are handled exactly (1.19 "has verify token" flag, 1.20.2
  login acknowledgement, 1.20.5 `shouldAuthenticate` flag), and the server's reported UUID and name must
  match the signed-in account.

### 4.6 Chat-signing keys (1.19+)

From 1.19 the client signs chat with a profile key pair issued by `/player/certificates`. The game needs
the private key to chat, so the vault serves it. A_mod can therefore sign chat as the player while the
key is valid (about two days). This is a deliberate, documented exception to "the game holds no account
secret". The key cannot log in, cannot `join` and cannot change the account, and Mojang can revoke it.

## 5. The local API channel (G4)

* **Server authentication.** The vault creates a new self-signed certificate for each session
  (RSA-2048, SHA-256, SAN `IP:127.0.0.1`, EKU serverAuth, valid one day) in `Vault/LocalCertificate.cs`.
  The game trusts it through a per-launch JKS truststore (`Launcher/JavaTrustStore.cs`). Another
  process squatting on the port first can't present a certificate the game accepts. The truststore also
  holds the Windows roots so that ordinary HTTPS from mods (skins, resource packs) still works. Public CAs
  do not issue certificates for `127.0.0.1`, so those roots can't vouch for an impostor on loopback.
* **Protocol versions.** TLS 1.2 and 1.3 only (`HttpsConnectionAdapterOptions.SslProtocols`).
* **Client authentication.** Each request carries the fake token as a bearer credential. The vault
  compares `SHA-256(supplied)` with `SHA-256(expected)` using `CryptographicOperations.FixedTimeEquals`.
  Hashing first gives a fixed-length, constant-time comparison that doesn't leak the expected length or
  a prefix. The token has 512 random bits: a 256-bit `jti` plus a 256-bit filler "signature". Only an
  online, loopback-only guessing attack is possible, and that is rate-limited (120/min).
* **Why the fake token is useless if stolen.** It is accepted only by the vault, only from loopback and
  only for the three allowlisted routes, and it expires with the session. Sent to Mojang, it gets 403
  (checked once against the real endpoint; `VALIDATION.md`).

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

* **Confidentiality and integrity.** AES-GCM is IND-CCA secure and INT-CTXT under a uniformly random key
  with unique nonces. Because each DEK encrypts exactly **one** message, nonce reuse under a key can't
  happen, whatever the random nonce turns out to be. That removes GCM's main misuse risk.
* **Binding.** The whole header (magic, version, wrap method, wrapped key) and the context are
  authenticated data. Changing any of them, or moving a file to another purpose or Windows user, makes
  decryption fail instead of producing different plaintext. The context is length-prefixed, so AD
  encodings can't be ambiguous. A test flips every single byte of an envelope in turn and checks that
  each one is rejected (`EnvelopeTests`).

### 7.2 Key wrapping (`Vault/WindowsKeyWrap.cs`)

| wrapId | Wrap(DEK) | Opens only with |
|---|---|---|
| 1 | DPAPI-CurrentUser(DEK, entropy) | this Windows user's DPAPI master keys |
| 2 | DPAPI-CurrentUser(RSA-OAEP-SHA256_TPM(DEK)) | this user's DPAPI keys **and** this physical TPM |

For wrapId 2 the RSA-2048 key is created in the **Microsoft Platform Crypto Provider** (the TPM 2.0)
with export policy *none*: the private key never exists outside the TPM. The vault picks wrapId 2 only
after a full wrap/unwrap round trip succeeds. Otherwise it falls back to wrapId 1, so a broken TPM
setup can't leave an unreadable file.

**Against A_offline:** DPAPI master keys are derived from the user's logon secret, so a disk image plus
an offline password guess (or a domain backup key) opens a wrapId 1 file. A wrapId 2 file additionally
needs the TPM-resident private key. That key can't be exported, so the copy is useless off the device.
**Crypto-shredding:** signing out deletes the TPM key, after which no copy of any earlier file can be
opened, even on the same PC.

**Compatibility and failure.** v1 files (raw DPAPI, before this format) are still read and rewritten as
v2 on the next save. Any decryption failure (tampering, a different PC or user, a cleared TPM) is
treated as "not signed in": the file is deleted and the user signs in again. A file is never partly
trusted.

**What it does not stop:** malicious code running *as the same user, on the same PC, unsandboxed* can
ask DPAPI and the TPM to unwrap, just as the vault does. Stopping that would need a user-presence
gesture for every use of the key (for example Windows Hello), which is listed as future work (§11).

## 8. Download integrity (G5)

* Game files come only from a fixed set of HTTPS hosts. Each Mojang file is checked against the SHA-1
  in Mojang's signed-over-TLS manifests. Mojang publishes no stronger hash. Using an existing file
  against this check would need a SHA-1 **second preimage**, since the attacker doesn't control
  Mojang's file. Collision attacks don't apply.
* Modrinth packs are checked against the pack's SHA-512 (or SHA-1). Non-HTTPS downloads are refused.
  Archives are extracted with checks against path traversal, links and size bombs (`PackTests`).
* Integrity isn't trust: a correctly downloaded mod can still be malicious. That is exactly why the
  game runs confined (§3).

## 9. Side issues and explicit non-goals

* **Managed-memory hygiene.** Secret byte arrays are zeroed (`CryptographicOperations.ZeroMemory`), but
  strings created by MSAL, JSON and HTTP can't be reliably erased in .NET. The vault never writes real
  tokens to logs, command lines, environment variables or files other than the envelope.
* **Logs** record classified events only: never headers, bodies, tokens or join hashes.
* **Same-user unsandboxed malware and administrators** are out of scope (§2). The vault does not defend
  against them, and says so in its documentation.
* **In-game abuse.** While the player is connected, A_mod controls that session: chat, movement, items.
  The goal is that nothing it gains outlives the session or works elsewhere.

## 10. Verification

`dotnet run --project tests/TokenVault.Tests -c Release` (runs in CI on Windows and Linux):

| Property | Test group |
|---|---|
| SHA-1 transcript hash known answers, positive and negative | `CryptoTests` |
| AES-CFB8 matches an independent OpenSSL vector, continuous over unaligned writes and reads | `CryptoTests` |
| Fake tokens unique and well-formed; only refresh tokens persisted | `TokenTests` |
| Envelope round trip; fresh DEK per seal; **every-byte tamper rejection**; context and key-wrap binding; truncation | `EnvelopeTests` |
| DPAPI envelope round trip (Windows); TPM-bound round trip where a TPM key exists | `EnvelopeTests` |
| PKCE required; wrong OAuth state refused | `OAuthCallbackTests` |
| TLS API: all join aliases denied, wrong fake denied, token substituted, real token never returned | `HttpTests` |
| Broker: mock server decrypts the broker's RSA-wrapped secret and checks the matching join hash; game never sees the encryption request; encrypted relay of 100 KB each way | `BrokerTests` |
| Offline-mode server refused before any authentication; game told why | `OfflineTests` |
| Join approval and the single-connection invariant | `ApprovalTests` |

What remains manual (real account, real TPM, real servers) is listed in `docs/ACCEPTANCE.md`.

## 11. Limitations and future work

1. **Formal model.** Model the broker handshake and the vault API in a symbolic protocol verifier
   (ProVerif or Tamarin), with A_mod as a compromised client role, and prove G2 (no `join` for a
   transcript whose secret the vault did not generate) under Dolev–Yao assumptions.
2. **User-presence-gated key.** Require a Windows Hello gesture to unwrap the TPM key (`NCRYPT_UI_POLICY`),
   extending G3 to same-user malware at the cost of a prompt each launch.
3. **Tamper-evident audit log.** Forward-secure MAC chaining (Bellare–Yee) of join and denial events, so
   a later compromise can't rewrite earlier entries undetected.
4. **Protocol.** The stream's lack of integrity and its 1024-bit RSA can only be fixed by Mojang, for
   example with an AEAD and an ephemeral key exchange in the login.
5. **Independent review.** This design has not been audited by a third party.

## References

* NIST SP 800-38D (GCM); SP 800-57 Part 1 Rev. 5 (key sizes).
* RFC 7636 (PKCE); RFC 8252 (OAuth 2.0 for native apps); RFC 8446 (TLS 1.3); RFC 8017 (PKCS #1 v2.2, OAEP).
* D. Bleichenbacher, "Chosen ciphertext attacks against protocols based on the RSA encryption standard
  PKCS #1", CRYPTO 1998.
* G. Leurent, T. Peyrin, "SHA-1 is a Shambles", USENIX Security 2020.
* M. Bellare, B. Yee, "Forward-security in private-key cryptography", CT-RSA 2003.
* Microsoft: AppContainer isolation; DPAPI (`CryptProtectData`); Platform Crypto Provider (TPM key storage).
* wiki.vg / minecraft.wiki, "Protocol encryption" (Minecraft login).
