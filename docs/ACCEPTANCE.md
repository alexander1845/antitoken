# Acceptance gates

Use a test account/server you control. Never paste a real credential into a shell,
issue, transcript, log or bug report. This repository has no public secret-dump API.

## Automated, no account required

`dotnet run --project tests/TokenVault.Tests -c Release` checks framing/compression
bounds, signed hashes, continuous AES-CFB8, fake JWTs, the refresh-only cache filter,
TLS API denial/substitution/non-disclosure, Fabric login query forwarding, online
broker encryption/relay and offline-server refusal.

The mock server owns an RSA private key and verifies that the join hash uses the
same fresh secret delivered in that exact upstream connection. The mock JVM sees
compression/login success, never the upstream encryption request. An independent
AES-CFB8 vector checks the stream implementation. These are regression tests, not a
substitute for a Minecraft account, client UI, Windows ACL or server compatibility test.

The test executable's `--probe-fixture <temporary-directory>` mode starts the real
HTTPS boundary backed by a synthetic upstream. It writes only a public certificate,
and emits a synthetic fake token to the coordinator's anonymous stdout pipe. It
stops when `<temporary-directory>/stop` exists. This is test code only, not a mode
in the production vault.

## Windows/live-account checks still required

1. **Actual sandboxed launch and online join.** On a clean Windows PC, press Play: the
   installer must fetch 26.1.2, Java and Fabric; approve the one-time loopback prompt; sign
   in with the built-in ID and with your own; add an online-mode server you control and join
   it from the in-game Multiplayer list. Import one pack of each supported format. Check rendering (OpenGL driver inside the
   AppContainer), audio, signed chat, mod/plugin handshakes, skins, resource packs,
   disconnect/reconnect and the configured mods folder. No unsandboxed fallback is allowed.
2. **Credential boundary.** Inspect the JVM command line and environment for an
   instrumented canary; only the fake token may appear. For real-token memory auditing, use a private debugger/harness that
   compares in memory without persisting/printing the credential. A grep of one heap
   dump alone does not prove absence from every native buffer or OS dump.
3. **Direct authentication fails.** Connect the fake-token client **directly to the
   original server**, with Authlib configured back to production and an ordinary
   public-CA truststore. Its fake-token join must be rejected. Changing only the
   Authlib hosts while continuing to use the authorized broker is not an appropriate
   negative test: the broker independently owns/authenticates its upstream connection.
4. **Forbidden actions.** Send PUT name-change, POST skin-change and both documented
   POST join paths to the vault. All return 403 even with the correct fake credential.
   Requests with a real token are not a special privileged path and also cannot join.
   Example non-authenticated denial checks (public certificate exported for testing):

   ```powershell
   curl.exe --cacert vault.pem -X POST https://127.0.0.1:25599/session/minecraft/join
   curl.exe --cacert vault.pem -X PUT https://127.0.0.1:25599/services/minecraft/profile/name/Test
   curl.exe --cacert vault.pem -X POST https://127.0.0.1:25599/services/minecraft/profile/skins
   ```

   Do not use `-k` in a test of TLS validation. In the production flow the launcher
   builds the truststore automatically; it never exports the private certificate key.
5. **Fake rejected by Mojang.** Submit only a synthetic fake token to the public join
   API in a controlled test. Expect failure; never use a live token as a CLI argument.
6. **Remote hash relay rejected.** Begin a second test client's handshake. Submit its
   hash to the vault through all join aliases, including with the legitimate fake
   bearer. They must return 403 and make zero outbound authentication calls. Only a
   connection freshly created by the broker can invoke its internal authenticator.
7. **Sandbox configuration (inspection, not exploitation).** While the game runs, confirm
   in Process Explorer that every java.exe in the job shows integrity "AppContainer" and
   the `TokenVault.MinecraftSandbox` package SID. Confirm with `icacls` that the sandbox
   SID appears only on: the instance folder, `assets\skins` and the per-launch `Run\<id>`
   folder (Modify, Low label); `libraries`, `assets`, the profile's `versions\<id>`
   folders, the Java home and an external mods folder (read/execute). It must NOT appear
   on `.minecraft` itself, `%LOCALAPPDATA%\TokenVault\Data` (protected DACL: you + SYSTEM
   only), the TokenVault.exe folder, or anywhere else in your profile.
8. **At rest.** After shutdown, inspect the vault's DPAPI plaintext with a dedicated
   test harness under your Windows identity: the MSAL AccessToken and IdToken buckets
   must be empty, while RefreshToken and necessary account metadata remain. Check
   requests.log contains no credentials. Do not persist the decrypted data.
9. **Stop/expiry.** Press Stop, close the window, and test expiry with a short
   `SessionMinutes`: the API listener and active broker connection must close and the
   whole game job must terminate. No already authenticated
   connection should survive the host process shutting down.

## Expected failures / supported scope

Unknown Minecraft/Authlib versions, offline upstreams, server-transfer login
intentions, unconfigured hosts, redirects, unexpected login packets, oversized or
malformed frames and forbidden HTTP actions are refused. The client can always be
disconnected by a malicious mod. A mod can still control the local authenticated
gameplay stream. Testing must not label this project an all-purpose mod sandbox.

## Saved sign-in encryption (release 1.0)

1. On a PC with a TPM 2.0: sign in, close Token Vault, and check the Security page reports
   "TPM + DPAPI, AES-256-GCM". Copy `%LOCALAPPDATA%\TokenVault\Data\vault.bin` to another PC or user
   and confirm Token Vault there asks for a fresh sign-in instead of using it.
2. On a PC without a TPM (or with it disabled): the Security page reports "DPAPI, AES-256-GCM" and
   sign-in is remembered across restarts.
3. With a sign-in saved by an earlier build: start 1.0, confirm no new sign-in is needed, and that the
   Security page shows the new format after the next token refresh.
4. Sign out, restore the old `vault.bin` from a copy, start Token Vault: it must ask for a new sign-in
   (the TPM key was destroyed).

## Release 1.1 checks (Windows)

1. **Game-only brokers.** While the game runs, open a TCP connection to a broker port (shown in the instance's
   `servers.dat`) from PowerShell: `Test-NetConnection 127.0.0.1 -Port <port>`. Activity shows "Refused a
   connection"; no approval prompt appears. Joining from the game's server list still works.
2. **Join prompt.** When the prompt appears, Join is greyed out for about a second and only becomes clickable
   while the prompt is the active window. Its position and button order change between prompts.
3. **Disconnect.** After joining, the green bar names the server. Disconnect drops the game to its
   "connection lost" screen; joining again asks again.
4. **Long sessions.** With `SessionMinutes` set to 2, join a server and keep playing past 2 minutes: the
   connection stays up. A new join after that is refused with an "expired" message in the game.
5. **Signed chat off.** Turn it off, launch 1.19.1+, join a server with `enforce-secure-profile=false`: chat
   works unsigned. With `enforce-secure-profile=true` the server refuses the join.
6. **Pack import.** Zip a `.minecraft` that contains mods for another Minecraft version and an
   `essential/microsoft_accounts.json`: the new instance has that version, and no account file.
7. **Updates.** Publish a signed pre-release build as `v<next>`; an older build installed in a user folder
   downloads it, shows "installed", restarts into it, and removes `TokenVault.exe.old`. Replace the
   release zip with a modified one: the update is refused and nothing changes.
8. **Statistics.** With a test PostHog project key, answer "No thanks": nothing is sent (check with a proxy).
   Answer yes: events arrive without account names, servers or paths.
