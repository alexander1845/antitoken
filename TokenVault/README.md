# Token Vault Launcher — Minecraft 26.1.2 / Fabric

Windows x64, C#/.NET 8, Java **25**, Fabric (example loader **0.19.5**),
Minecraft protocol **775**, Mojang Authlib **7.0.63**. MIT licensed, open source.

This is a security-focused implementation with automated protocol/API tests.
It is **not yet a Windows/live-account-validated release**. Read
[VALIDATION.md](docs/VALIDATION.md) for completed checks and remaining gates.
Do not treat passing synthetic tests as a promise that malicious mods cannot
steal items. They can still operate the already authenticated game.

## What changed from the proposed HTTP vault

Allowing the JVM to submit arbitrary `/session/minecraft/join` requests would let
a mod relay another PC's login hash to the vault. Hiding the bearer token alone
does not stop that attack. Therefore **every JVM-facing join request returns 403**,
including requests made with the correct fake token. Configuration cannot change this.

A trusted Minecraft-protocol broker connects to one administrator-configured
server. It generates the upstream AES secret, computes the join hash from that
connection, calls Mojang internally, and retains encryption state. The JVM connects
to the broker's loopback Minecraft listener and never receives the upstream secret,
the remote encryption handshake, or the real OAuth/Minecraft bearer credentials.
Fabric login plugin messages, configuration, signed chat and gameplay packets pass
through; installed mods are unchanged. The broker does not expose a generic signing,
join-hash, arbitrary target-server, or arbitrary HTTP-forwarding API.

The HTTPS vault provides a small, fixed API surface for player attributes,
profile/chat certificates and public service keys. See [ALLOWLIST.md](docs/ALLOWLIST.md).
The JVM receives a unique fake JWT. The fake is invalid at Mojang. Disabling or
repointing the HTTP vault cannot turn it into a real credential.

## Security boundary and honest limits

The source, ports, endpoints, client ID, algorithms and protocols are public.
Security depends on OS identity separation, access controls, random secrets and
authenticated TLS. Obscurity is not a defense.

In isolated mode, real credentials exist only in the dedicated vault process,
not in the launcher process or JVM. OAuth, Xbox and Minecraft access tokens remain
in memory; a filtered MSAL cache persists refresh tokens encrypted with DPAPI
`CurrentUser`. Non-secret account/cache metadata is also persisted inside that blob.
The TLS private key is ephemeral. Only its public certificate is written for the
JVM's truststore. No API secrets, fake tokens or real tokens are written by our logs.

The three requested limits are reproduced verbatim below:

> (a) data-in-use — at login and relaunch the real token is briefly in cleartext RAM, so same-user malware present at that instant wins;
>
> (b) in-session abuse — a mod can ask the vault to perform allowlisted actions (join server, chat) while the game runs; the vault can rate-limit/log but cannot distinguish a mod's request from the user's;
>
> (c) admin/SYSTEM malware defeats everything — that's AV's job.

**Implementation-specific corrections to that wording:**

* Access tokens remain usable in vault RAM for the session, not only briefly at
  login. A same-user development-mode vault is vulnerable throughout its lifetime.
  Separate-user mode isolates the vault from non-admin code running as the gaming
  user, including during authentication; it does not protect against malware
  already running as the vault user. Browser compromise remains an independent risk.
* Arbitrary join hashes are **not** allowlisted. The broker can authenticate only
  the connection it owns. A mod can nevertheless connect to that local broker,
  control its plaintext gameplay side, relay that side to someone elsewhere, or
  transfer/drop items through the existing game. This project does not sandbox mods
  or prove human intent. It blocks bearer-token extraction and the arbitrary-hash
  authentication relay, not all remote control or item theft.
* Admin/SYSTEM compromise is outside this boundary. Antivirus is not a guarantee
  that such compromise will be detected or prevented.

Other relevant limits:

* A mod can steal **other credentials already readable by its Windows account**:
  old launcher tokens, browser sessions, other launchers' caches, etc. This launcher
  does not revoke or clean them. Use a credential-free Windows gaming account and
  make game assets/mods accessible to it; keep the primary account and vault account
  separate. Keeping another usable Minecraft token in the normal launcher defeats
  the overall goal even though this vault's token remains isolated.
* Managed strings created by MSAL, JSON and HTTP APIs cannot reliably be zeroed.
  Owned byte arrays are cleared where possible; “zero all token copies” and “never
  appears in paging/crash dumps” are not guarantees .NET or this program can make.
  Do not enable vault process dumps. Protect the OS disk and vault user profile.
* Profile certificate responses deliberately contain a chat private signing key.
  Minecraft may cache that key. It is not the account's bearer token, but a malicious
  mod can misuse it. The refresh-token-only persistence claim covers the vault's
  account-token storage, not every secret generated by Minecraft or the OS.
* A truststore containing only the vault certificate can break unrelated HTTPS
  features/mods, skins or resource-pack downloads. A malicious mod can also create
  its own TLS context; the truststore is not a network sandbox.
* No guarantee against denial of service, local input capture, account theft through
  unrelated credentials, or malicious actions permitted by the game server.

## Prerequisites

1. Windows x64, .NET 8 SDK for building, and a **JDK 25** with `java.exe` and
   `keytool.exe`. A JDK is required for the source-mode Authlib preflight.
2. A purchased Minecraft Java account with multiplayer permission.
3. Your **own approved Microsoft/Minecraft public-client application ID**.
4. Minecraft **26.1.2** and the configured Fabric version already installed in the
   standard launcher layout: `versions/`, `libraries/`, `assets/`. Run that profile
   once normally to provision assets, then close it. This project does not implement
   a Minecraft/Fabric downloader, redistribute their JARs, or accept alternate
   launcher-specific directory layouts. Supply existing mods through `ModsDirectory`.
5. One explicit online-mode server host/port. Use the actual host/port; DNS SRV
   discovery, automatic server transfers, Realms and arbitrary server selection are
   not implemented. Switch the target through the protected config, then restart.

## Register the application

1. In Microsoft Entra **App registrations**, create your own app supporting
   **personal Microsoft accounts** (or organizations plus personal accounts).
2. Configure it as a **public desktop/mobile client**, without a client secret.
   Add the loopback redirect URI `http://127.0.0.1:25597/` to the public-client
   redirect URI list. If the portal restricts literal loopback IP entry, use the
   documented application-manifest method. The URI and port must match `OAuthPort`.
3. The code uses the `consumers` authority and requests `XboxLive.signin`.
   MSAL itself adds the reserved `openid`, `profile` and `offline_access` scopes.
   Do **not** manually add reserved scopes to the `AcquireToken*` scope array.
4. Follow Minecraft's application review/registration process for access to
   Minecraft Services. Azure registration alone may not permit the final exchange.
   A 403 at `authentication/login_with_xbox` is a feasibility blocker until your app
   is approved. Do not copy the official launcher's or another launcher's client ID.
5. Set `ClientId` in your configuration. Run the standalone `auth` command before
   trying a game launch. It prints **username and UUID only**, never credentials.

OAuth uses MSAL's system-browser authorization-code flow and PKCE. There is no
embedded browser, password form, device-code fallback, confidential-client secret,
or password/cookie collection. The browser handles Microsoft credentials.
The MSAL `ICustomWebUi` adapter opens only that system browser; it does not embed
a webview. Its Kestrel callback binds literal `127.0.0.1`, validates state and PKCE
presence, and passes the authorization response back to MSAL for redemption.
This avoids a mismatch with MSAL's default `localhost` HttpListener prefix.
XSTS errors for missing Xbox profiles, child/family restrictions, region and age
verification have fixed, non-secret messages.

References: [MSAL system browser](https://learn.microsoft.com/en-us/entra/msal/dotnet/acquiring-tokens/using-web-browsers),
[OAuth/PKCE and loopback registration](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow),
[redirect URI restrictions](https://learn.microsoft.com/en-us/entra/identity-platform/reply-url),
[Minecraft application access](https://help.minecraft.net/hc/en-us/articles/16254801392141),
[MSAL cache](https://learn.microsoft.com/en-us/entra/msal/dotnet/how-to/token-cache-serialization).
If the Minecraft help link moves, contact Minecraft support for current app-ID
authorization instructions; this repository cannot grant approval.

## Build and test

```powershell
dotnet restore TokenVault.sln
dotnet build TokenVault.sln -c Release
dotnet run --project tests/TokenVault.Tests -c Release
```

Or run `scripts/Build.ps1` to build, test and publish self-contained Windows x64
executables in `artifacts/Vault` and `artifacts/Launcher`. The console test harness
returns a nonzero exit code on failure; it is run with `dotnet run`, not `dotnet test`.
The GitHub Actions workflow runs these gates on Windows and Linux. No CI run is
claimed merely because a workflow file exists.

## Isolated installation (recommended)

1. Copy `config.example.json` to `config.local.json` and fill in the client ID,
   actual server, Java/keytool paths, installed Fabric profile, directories and ports.
   `MinecraftDirectory` is the standard install root; `GameDirectory` is the instance;
   `ModsDirectory` is passed through `fabric.modsFolder`. No mod files are rewritten.
2. Build with `scripts/Build.ps1`.
3. In elevated PowerShell, run:

   ```powershell
   .\scripts\Install-Isolated.ps1 -Config .\config.local.json -GameUser 'YOURPC\GamingUser'
   ```

   Setup creates a new non-admin local vault account, prompts for its Windows
   password, installs binaries under Program Files, and writes protected settings
   and private data under ProgramData. It refuses to overwrite an existing install.
   It does not store that password. Keep the vault account out of Administrators.
4. Sign into the dedicated vault Windows account once and initialize its system
   browser. Start `TokenVault.Vault.exe auth <config-path>` there to test login.
   For maximum separation, run the host from that account's own desktop and switch
   back to the gaming account while leaving the vault session running.
5. Alternatively, `scripts/Start-Vault.ps1` starts the host with alternate Windows
   credentials and a loaded user profile. Browser behavior in this mode must be
   verified on your Windows installation. It never falls back to a same-user vault.
6. Run `scripts/Start-Game.ps1` as the gaming user. The launcher verifies the named
   pipe server's Windows identity, receives only the fake/public descriptor, creates
   the public-only JKS, probes real Authlib over loopback TLS, and launches Fabric
   with `--quickPlayMultiplayer 127.0.0.1:25598`.

The host refuses identity/permission mismatches, unexpected Authlib/protocol versions
are refused by the launcher, and refused API operations stay refused. Closing the
vault or reaching the configured session deadline closes broker connections.
Restart/login to renew; the host does not silently keep an unlimited session alive.

## Development fallback

Set `HardeningMode` to `same-user-development` and `DataDirectory` to a writable
private folder. The explicit combined fallback runs launcher and vault in the same
process (the game remains a separate fake-token JVM):

```powershell
dotnet run --project src/TokenVault.Vault -- dev config.local.json
```

Alternatively use two terminals under the same Windows user:

```powershell
dotnet run --project src/TokenVault.Vault -- host config.local.json
dotnet run --project src/TokenVault.Launcher -- launch config.local.json
```

Both development options keep the real token out of the JVM, but offer **no
protection from same-user memory-reading malware**. The combined command is refused
unless the configuration explicitly selects development mode.

## Configuration and compatibility

* Ports are loopback-only. `OAuthPort`, `HttpsPort`, `GamePort` must be distinct.
* `HardeningMode`, both Windows SIDs and paths are checked in isolated mode.
* `Allowlist` can narrow the compiled API ceiling; `*` does not grant anything.
* `ObserveDeniedEndpoints` enables sanitized denied-path detail, **not permission**.
* `SessionMinutes` caps credential/broker availability; HTTP operations are limited
  to 60 allowed calls/minute, one active game connection and a three-second reconnect
  interval. Logs contain no bodies, headers, tokens, or join hashes.
* Only protocol 775 / 26.1.2 is accepted. Example Fabric loader 0.19.5 can be changed
  to another installed compatible loader by updating both version/profile fields.
* The launcher pins Authlib 7.0.63 to Mojang's published SHA-1 content hash. Its
  executable probe checks all three custom host properties and successfully uses
  the vault's self-signed certificate before allowing launch. A pinning change or
  ignored overrides cause refusal, not fallback to real credentials in the JVM.
* The passphrase/Argon2 layer and outbound-token tripwire are optional proposals,
  **not implemented**. A passphrase alone would not isolate an unlocked same-user
  process; passive packet scanning cannot reliably find a token inside TLS.

See [ACCEPTANCE.md](docs/ACCEPTANCE.md) for the Windows/account checks, the stronger
relay regression test, and why the original “repoint Authlib” test needs a precise
interpretation with a connection-owning broker.

## Source history

The archive includes `history.bundle` with stages 1–7 and follow-up test/review
commits. To reconstruct the repository: `git clone history.bundle token-vault`.
No Microsoft, Mojang, Fabric, or JDK binaries are included in the source archive.
External packages retain their own licenses.
