# Token Vault — sandboxed launcher for Minecraft 26.1.2 / Fabric

Windows 10/11 x64, C#/.NET 8 (WPF GUI), Java **25**, Fabric (example loader **0.19.5**),
Minecraft protocol **775**, Mojang Authlib **7.0.63**. MIT licensed, open source.

**Goal:** play with Fabric mods you don't fully trust, without any mod being able to steal your
Minecraft session token, your Microsoft refresh token, or other sign-in data on your PC.
One app, one window, one Play button, your normal Windows account. No second Windows user, no
official launcher, no app registration needed to test.

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
   listener (one per server you add; they appear in the game's Multiplayer list). The vault opens
   its own connection to that server, generates the
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
     startup items, or the shared game install (`libraries`, `versions`, Java).
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

## Using it

1. Run `TokenVault.exe`.
2. Press **Play**. The first time, Token Vault:
   * downloads Minecraft 26.1.2, its Java runtime and Fabric from Mojang/Fabric
     (HTTPS, every file checked against the published SHA-1) into `%LOCALAPPDATA%\TokenVault\Minecraft`.
     The official launcher is not needed and is not touched.
   * asks Windows for the one-time sandbox networking approval (see above),
   * opens Microsoft's sign-in page in your browser. Choose your account and you're done.
     Later launches reuse the saved sign-in.
3. Add the servers you play on under **Servers**. They show up in the game's Multiplayer list.
   Servers added inside the game can't sign you in, because the game never has your account.

### Mods and modpacks

**Import modpack…** (or drag files onto the window) accepts:

| What | Notes |
|---|---|
| Modrinth `.mrpack` | Mods download from Modrinth/GitHub/GitLab only, checked against the pack's SHA-512/SHA-1 |
| CurseForge modpack `.zip` (`manifest.json`) | Uses CurseForge's public download links. Files whose authors block third-party downloads are listed with links so you can download them and drop them on the window |
| Prism Launcher / MultiMC export `.zip` (`mmc-pack.json`, `instance.cfg`) | Copies the instance's `.minecraft` folder |
| Any `.zip`, `.7z`, `.rar`, `.tar`, `.tar.gz` or folder | If it contains a `mods/` folder, that whole game folder (config, resource packs…) is imported. Otherwise every `.jar` becomes a mod |
| `.jar` files | Added to the selected instance |

Each pack becomes its own instance in the **Library**, in a new folder the sandbox has never had
access to. Sign-in files that other launchers keep (`accounts.json`, `launcher_accounts.json`,
`launcher_msa_credentials.bin`, …) are never copied, even from a zipped-up `.minecraft`.
Packs for other Minecraft versions, or for Forge, NeoForge or Quilt, are refused before anything
is downloaded. Token Vault only plays Minecraft 26.1.2 with Fabric.

### Sign-in without registering an app

Microsoft's sign-in always needs some registered application ID. By default Token Vault uses the
public ID that **Prism Launcher** publishes in its source code (`c36a9fb6-…`). It is not a secret, so
you can test without registering anything. Microsoft's consent page will say "Prism Launcher".
Your password still only goes to Microsoft, and the tokens stay in Token Vault.
If you distribute Token Vault, register your own app (personal Microsoft accounts, public client,
redirect `http://127.0.0.1:25597/`, Minecraft API approval) and put its ID in
**Settings → Microsoft application ID**. If the browser flow doesn't work, enable
**Settings → Sign in with a code**.

**Smart App Control / WDAC:** if Windows Smart App Control is on, it blocks unsigned programs,
including a locally built `TokenVault.exe`. Sign the build, or decide for yourself whether to change
that Windows setting. Token Vault does not touch it.

## Build and test

```powershell
dotnet build TokenVault.sln -c Release
dotnet run --project tests/TokenVault.Tests -c Release
```

Any .NET 8 or newer SDK works. `scripts/Build.ps1` also publishes a self-contained single file,
`artifacts/TokenVault/TokenVault.exe`; keep `AuthlibProbe.java` next to it. CI builds and runs the
tests on Windows and Linux, and uploads the Windows build.

## Projects

| Project | Role |
|---|---|
| `TokenVault.App` | WPF window: library, Play, servers, protection status, settings |
| `TokenVault.Vault` | Microsoft/Xbox/Minecraft sign-in, DPAPI refresh cache, HTTPS API, connection brokers |
| `TokenVault.Launcher` | Game installer, installed-profile resolver, AppContainer sandbox, folder policy, JKS truststore, `servers.dat` |
| `TokenVault.Packs` | Modpack/archive import (Modrinth, CurseForge, Prism/MultiMC, zip/7z/rar/tar, folders, jars) |
| `TokenVault.Core` | Settings, packet I/O, Minecraft crypto, fake JWT |

## Compatibility notes

* Only protocol 775 / 26.1.2 is accepted, and Authlib is pinned to 7.0.63 by hash.
* The game's truststore contains the vault's loopback certificate plus your Windows trusted roots,
  so normal HTTPS from the game and mods (resource packs, skins) keeps working.
* The sandbox can't write `%APPDATA%` or your user folder. Mods that insist on writing there will
  log errors. `user.home` and `java.io.tmpdir` are pointed at sandbox folders.

## Source history

`history.bundle` holds the earlier stages (`git clone history.bundle token-vault`). No Microsoft,
Mojang, Fabric or JDK binaries are included.
