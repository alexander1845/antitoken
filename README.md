# Token Vault — sandboxed launcher for Minecraft 26.1.2 / Fabric

Windows 10/11 x64, C#/.NET 8 (WinForms GUI), Java **25**, Fabric (example loader **0.19.5**),
Minecraft protocol **775**, Mojang Authlib **7.0.63**. MIT licensed, open source.

**Goal:** play with Fabric mods you don't fully trust, without any mod being able to steal your
Minecraft session token, your Microsoft refresh token, or other sign-in data on your PC.
One app, one window, your normal Windows account. No second Windows user.

> Status: compiles cleanly; the protocol/API regression suite runs in CI. The AppContainer launch
> has **not** yet been validated on a real game install. See [VALIDATION.md](docs/VALIDATION.md).
> If the sandbox cannot run something, the game fails to start. It never falls back to an
> unsandboxed launch.

## How it works

```
 ┌──────────────── TokenVault.exe (your Windows user, normal integrity) ────────────────┐
 │  Microsoft sign-in (system browser, PKCE)  →  Xbox  →  Minecraft access token         │
 │  Real tokens live ONLY here.  Refresh token on disk: DPAPI, private folder.           │
 │                                                                                        │
 │  127.0.0.1:25599  HTTPS API — 3 allowlisted endpoints, fake→real token substitution   │
 │  127.0.0.1:25598  Connection broker — logs in to YOUR configured server itself        │
 └──────────────────────────────────▲─────────────────────────────────────────────────────┘
                                    │ fake token, loopback only
 ┌──────────────────────────────────┴───── Windows AppContainer sandbox (Low integrity) ──┐
 │  java.exe → Fabric → Minecraft → every mod                                              │
 │  can read: libraries/, assets/, versions/<profile>/, Java runtime, mods folder          │
 │  can write: the instance folder, assets/skins (skin cache), a per-launch temp folder    │
 │  cannot: read your other files, open TokenVault.exe's memory, write elsewhere           │
 └─────────────────────────────────────────────────────────────────────────────────────────┘
```

1. **The real credentials never enter the game.** The JVM gets a random fake JWT. Mojang rejects
   it, so stealing it is useless. Authlib is pointed at the vault's local HTTPS API, which swaps in
   the real token only for three fixed read-only endpoints (attributes, chat certificate, public
   keys) and returns 403 for everything else. That includes every `/session/minecraft/join` alias,
   name/skin changes, and arbitrary URLs. See [ALLOWLIST.md](docs/ALLOWLIST.md).
2. **Server login is done by the vault, not the game.** The game connects to a local Minecraft
   listener. The vault opens its own connection to the one configured server, generates the
   encryption secret, calls Mojang's join endpoint itself, then relays the game traffic. A mod can't
   ask the vault to authenticate some other connection (for example, relaying a join hash from an
   attacker's PC), because there is no API for it.
3. **The game and all mods run in an AppContainer.** This is the same Windows sandbox used for
   Edge and UWP apps. Creating it needs no admin rights and no extra account. The container has its
   own SID and runs at Low integrity, so Windows refuses it:
   * **your files.** It can't open anything not explicitly granted to the container: browser cookies
     and saved passwords, the official launcher's sign-in files in `.minecraft`, Discord tokens,
     documents, and Token Vault's own saved sign-in (`%LOCALAPPDATA%\TokenVault\Data`, a private
     folder with inheritance cut off).
   * **the vault's memory.** Low-integrity processes can't open normal-integrity processes for
     reading or injection. The real token in TokenVault.exe's RAM is out of reach.
   * **writes outside its folders.** Mods can't replace TokenVault.exe, the config, other launchers,
     startup items, or the shared `libraries`/`versions` files that the official launcher would run
     unsandboxed later.
   * **your clipboard** (default). Passwords you copy from a password manager while playing stay out
     of reach. You can re-enable copy/paste in the window.
   * **input to other windows.** UIPI blocks Low-integrity processes from sending messages to normal
     windows.

   A job object makes everything the game starts die with it, or with Token Vault.
   Microsoft treats AppContainer escapes as security-boundary bugs and fixes them in Windows Update.
4. **Sign-in never overlaps a running game.** The browser sign-in happens before launch. Sign-in and
   sign-out are disabled while the game runs, so no mod is alive during the OAuth flow.

### One-time admin prompt (not an account)

Windows blocks AppContainers from connecting to `127.0.0.1` by default. On first Play, Token Vault
asks once for UAC approval to run Windows' own
`CheckNetIsolation LoopbackExempt -a -p=<this sandbox's SID>`. That exempts only this sandbox. It
creates no account, starts no service, and changes no other setting. To undo it:
`CheckNetIsolation LoopbackExempt -d -p=<SID>` (elevated).

## What it does NOT protect against (honest limits)

* **In-game abuse.** A malicious mod still controls the game session you are playing. It can chat,
  move or drop items, disconnect you, and use the chat-signing key Minecraft needs for signed chat.
  It cannot take your account with it after you close the game.
* **Malware outside the sandbox.** Anything running unsandboxed as your Windows user can read what
  you can, including the vault's memory and its DPAPI-protected refresh token. Admin/SYSTEM malware
  defeats everything. That is antivirus territory. The old "separate vault account" design defended
  against same-user malware and this one does not. It defends against what you asked for: mods.
* **Running the same mods elsewhere.** If you also play these mods through the official launcher,
  Prism, or similar, they run unsandboxed there and can steal everything. Use Token Vault for modded
  play.
* **Phishing.** A mod can show a fake "log in" screen. Token Vault never asks for a password inside
  the game. Sign-in only ever happens in your browser, before the game starts.
* **Keystrokes typed into other apps while the game is running.** The sandbox shares your desktop.
  Windows' UIPI blocks many input-snooping techniques for Low-integrity processes, but this has not
  been audited here. Close the game before typing passwords elsewhere if you want to be sure.
* **Loopback exposure.** The exemption lets the sandbox reach any `127.0.0.1` port, not just the
  vault's. Don't run sensitive unauthenticated local services while playing.
* **Memory hygiene.** Managed strings from MSAL/JSON/HTTP can't be reliably zeroed. Token Vault never
  writes real tokens to logs, files (besides the DPAPI blob), command lines, or the game environment.

## Prerequisites

1. Windows 10/11 x64 and a purchased Minecraft Java account with multiplayer permission.
2. Minecraft **26.1.2** plus Fabric for 26.1.2, installed with the official launcher and the Fabric
   installer. Run the Fabric profile **once** in the official launcher (to download libraries,
   assets and Java), then close it. Java comes from that install automatically. A JDK 25 is optional
   and enables an extra Authlib self-check before each launch.
3. **Your own approved Microsoft/Minecraft application (client) ID.** See below.
4. One online-mode server address. DNS SRV records, server transfers and Realms are not supported.

## Register the application

1. In Microsoft Entra **App registrations**, create an app that supports **personal Microsoft
   accounts**. Configure it as a **public client / mobile & desktop** app with no secret, and add
   the redirect URI `http://127.0.0.1:25597/`.
2. Follow Minecraft's application review process for Minecraft Services access
   ([help article](https://help.minecraft.net/hc/en-us/articles/16254801392141)). Until it is
   approved, `login_with_xbox` returns 403. Don't reuse another launcher's client ID.
3. Paste the client ID into **Advanced → Microsoft app ID** in Token Vault.

Sign-in uses MSAL's system-browser authorization-code flow with PKCE. There is no embedded browser,
password form, device code, or client secret.

## Use it

1. Build it (below), or download the `TokenVault-win-x64` artifact from CI.
2. Run `TokenVault.exe`. Fill in **Server**, pick the **Fabric profile**, and check that the
   **Minecraft folder** points at your `.minecraft`.
3. Put your mods in the **Mods folder**. The **Open** button opens it. By default this is
   `%LOCALAPPDATA%\TokenVault\Instance\mods`. Saves, options and logs go to the **Instance folder**.
   Token Vault refuses to use `.minecraft` itself (or your user folder, AppData, etc.) as the
   instance, because the sandbox would then be able to read the official launcher's sign-in files.
4. Press **Play**. The first time, approve the one-time networking prompt and sign in in your
   browser. The game opens and joins your server directly.
5. **Stop game** or closing Token Vault ends the game and the session.

Settings live in `%LOCALAPPDATA%\TokenVault\Data\config.json`. Advanced options (ports,
`SessionMinutes`, `Allowlist`, `ObserveDeniedEndpoints`) can be edited there; see
`config.example.json`.

**Smart App Control / WDAC:** if Windows Smart App Control is on, it blocks unsigned executables,
including a locally built `TokenVault.exe`. Sign the build with a trusted code-signing certificate,
or decide for yourself whether to change that Windows setting. Token Vault does not touch it.

## Build and test

```powershell
dotnet restore TokenVault.sln
dotnet build TokenVault.sln -c Release
dotnet run --project tests/TokenVault.Tests -c Release
```

`scripts/Build.ps1` does all of that and publishes a self-contained single-file
`artifacts/TokenVault/TokenVault.exe`. Keep `AuthlibProbe.java` next to it. CI runs the build and
the tests on Windows and Linux, and uploads the Windows build.

## Projects

| Project | Role |
|---|---|
| `TokenVault.App` | WinForms window: settings, sign-in, Play/Stop, log |
| `TokenVault.Vault` | OAuth/Xbox/Minecraft auth, DPAPI refresh cache, HTTPS API, connection broker |
| `TokenVault.Launcher` | Installed-profile resolver, AppContainer sandbox, folder policy, JKS truststore |
| `TokenVault.Core` | Config, packet I/O, Minecraft crypto, fake JWT |

## Compatibility notes

* Only protocol 775 / 26.1.2 is accepted, and Authlib is pinned to 7.0.63 by hash.
* The game's truststore contains the vault's loopback certificate plus your Windows trusted roots,
  so normal HTTPS from the game and mods (resource packs, skins) keeps working.
* The sandbox can't write `%APPDATA%` or your user folder. Mods that insist on writing there will
  log errors. `user.home`, `java.io.tmpdir` and LWJGL/JNA extraction are pointed at sandbox folders.

## Source history

`history.bundle` holds the earlier stages (`git clone history.bundle token-vault`). No Microsoft,
Mojang, Fabric or JDK binaries are included.
