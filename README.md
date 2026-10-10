# Token Vault

**Play Minecraft with mods you don't fully trust, without risking your account.**

Most account thefts in modded Minecraft are simple: a mod reads the session token the game holds in
memory, or the sign-in files other launchers keep, and sends them to someone else, who then plays as you,
or worse, takes over your Microsoft account. Token Vault is a Minecraft launcher for Windows built to stop
that. The game and every mod run in a Windows sandbox and never receive your real sign-in. Token Vault
keeps it and handles the parts of signing in that need it. A bad mod can still misuse the game while you
play (see [what it doesn't protect against](#what-it-doesnt-protect-against)), but it can't walk off with
your account.

It uses your normal Windows account, has one Play button, and needs no second user and no official
launcher.

> **Status: early release.** Tested end to end on Windows with vanilla and Fabric, including joining
> online-mode servers. Quilt, Forge and NeoForge are experimental. See [Limits](#what-it-doesnt-protect-against).

---

## Download and first run

1. Download **TokenVault-win-x64.zip** from the [latest release](../../releases/latest) and unzip it
   anywhere you can write to (not Program Files, so it can update itself). `AuthlibProbe.java` is only
   used for an optional self-check when you point Token Vault at a JDK.
2. Run `TokenVault.exe`. Nothing else needs to be installed.
3. Press **Play**. The first time:
   * Windows asks once for administrator approval for the sandbox (see [below](#the-one-time-windows-prompt)).
   * Minecraft, its Java runtime and the mod loader download from Mojang and the loader's servers. Every
     file is checked against the hash its publisher lists (CurseForge mods in packs excepted: CurseForge
     doesn't publish hashes).
   * Your browser opens Microsoft's sign-in page. Your password only ever goes to Microsoft.
4. Add your servers under **Servers**. They appear in the game's Multiplayer list.

### "Windows protected your PC"

New programs that aren't signed by a publisher Windows recognises get this blue SmartScreen screen.
Click **More info → Run anyway**. Code-signed release builds don't show this screen
(see [Releasing](#releasing)). Until then the warning is expected, and you can check the build by
comparing it with the CI artifact or by building it yourself.

If **Smart App Control** is turned on, Windows blocks unsigned programs completely and has no "Run
anyway" option. You'll need a signed release.

## Features

* **One-click Play** for any Minecraft release from 1.8 onwards, vanilla or Fabric. Quilt, Forge and
  NeoForge are experimental.
* **Modpack import**: drag a Modrinth `.mrpack`, CurseForge `.zip`, Prism/MultiMC export, any
  `.zip`/`.7z`/`.rar`/`.tar` or loose `.jar` files onto the window. Each pack becomes its own instance,
  set up for the Minecraft version and loader the pack (or its mods) names. From a zipped game folder
  only mods, settings, packs and worlds are copied; other launchers' and clients' sign-in files never are.
* **Join approval**: before anything signs in to a server as you, Token Vault asks in its own window,
  which the game can't click. Join only works after the window has been on screen for a moment, so the
  game can't time it under one of your clicks.
* **Live connection bar** with a **Disconnect** button while you're signed in to a server.
* **Activity view**: every join, blocked join and blocked account request, in plain language.
* **Clipboard protection**: by default the game can't read what you copy, such as passwords from a
  password manager.
* **Signed chat switch** (Minecraft 1.19+): turn it off if your servers don't need it (see below).
* **Automatic updates** from this repository's releases, installed only if they carry Token Vault's
  release signature.

## How it protects you

```
 Token Vault (your Windows user)                    Windows sandbox (low integrity)
 ───────────────────────────────                    ───────────────────────────────
 your real sign-in, encrypted on disk               Java → Minecraft → every mod
 local API: 3 read-only calls  ◄─── fake token ──   can't read your files
 server login broker           ◄─── game traffic ─  can't read Token Vault's memory
```

1. **The game gets a fake token.** It is random and useless to anyone who steals it. The game's
   account requests go to Token Vault, which forwards only a fixed list of five calls (profile and skin
   lookups, account settings, and the chat-signing key) with your real token and refuses everything else,
   including server sign-ins, name and skin changes.
2. **Token Vault signs in to servers itself.** The game connects to Token Vault, which does the
   encrypted login with the server and then passes the game traffic through. A mod can't ask Token Vault
   to sign in to a connection of its own, because the secret that ties a sign-in to a connection is
   generated and kept by Token Vault, and only the game's own processes can use these connections. The
   server sees the game's own login packets (one small difference on 1.19–1.19.2); the relay adds a hop
   on your own PC and decrypts at roughly 100 MB/s on one CPU core.
3. **The game runs in an AppContainer**, the Windows sandbox used for browser and Store apps. It can't
   read your documents, browser data or other launchers' sign-in files. It can't read Token Vault's
   memory, change files outside its game folders, or send input to other windows.
4. **Your saved sign-in is encrypted** with AES-256-GCM under a key protected by Windows DPAPI and, where
   the PC has one, its **TPM** chip. With the TPM, a copied file is useless on any other computer and
   signing out destroys the key. Without a TPM, a copy can be opened by someone who also has your Windows
   password. Signing out doesn't cancel the sign-in at Microsoft; to do that, remove the app at
   account.live.com/consent/Manage.

The full design, threat model and cryptographic analysis are in
[docs/CRYPTOGRAPHY.md](docs/CRYPTOGRAPHY.md).

### The one-time Windows prompt

Windows needs an administrator's approval once for three small changes that apply only to Token
Vault's sandbox:

* let it connect to Token Vault on this PC (`CheckNetIsolation LoopbackExempt`),
* let it see folder **names** at the top of your system drive, which Java needs,
* mark `C:\TokenVault` as a folder the sandbox may write to (a low integrity label; access is still
  limited by the folder's private permissions).

No account is created, no service is installed, and nothing else changes.

## What it doesn't protect against

* **What happens while you're on a server.** A malicious mod controls that connection: it can chat,
  trade, drop items, or quietly hand the connection to someone else who then plays as you there until
  you disconnect. What they do in that time (giving items away, linking the account to something on that
  server, getting it banned) can last. If anything looks wrong, press **Disconnect** in Token Vault. A mod
  can't sign in as you afterwards. Only play valuable accounts with mods you trust.
* **The chat-signing key.** With signed chat on (the default, because many servers require it), a mod can
  copy the key and sign chat as you for about two days. It can't sign in with it. Turn signed chat off on
  the Security page if your servers don't need it.
* **Servers you add.** A server on your list can pass your sign-in through to a different server. Only add
  servers you trust.
* **Malware already on your PC.** Programs running outside the sandbox as you (or as administrator) can
  read whatever you can. That's antivirus territory.
* **Playing the same mods elsewhere.** In another launcher those mods run unsandboxed.
* **Fake login screens.** Token Vault never asks for your password inside the game. Sign-in only happens
  in your browser, before the game starts.
* **Local services.** The sandbox can reach anything listening on `127.0.0.1` while you play.
* **Realms and server transfers** don't work: both need the game to sign in by itself.
* **The sandbox shares your desktop.** It can't send input to other windows or read the clipboard (by
  default); whether it can take screenshots of other windows hasn't been tested.

## Updates

Token Vault checks this repository's releases when it starts and every six hours. When there is a newer
one, it downloads it in the background, checks it against Token Vault's release signature and puts it in
place; the new version runs the next time you open Token Vault (or press **Restart now**). A release
without a valid signature is never installed. You can turn update checks off in **Settings**.

## Usage statistics

Off unless you say yes. Token Vault asks once; you can change it in **Settings**. If you agree, it sends
anonymous events to PostHog: app and Windows version, the Minecraft version and loader you launch, and
whether launches and joins worked, with a random id for this install. It never sends your account name,
servers, mods, files or anything from the game. Builds without a PostHog project key send nothing.

## Where things are

| | |
|---|---|
| Game files, instances | `C:\TokenVault` (private to your Windows user) |
| Settings, saved sign-in, activity log | `%LOCALAPPDATA%\TokenVault\Data` (never shared with the game) |
| Downloaded updates (temporary) | `%LOCALAPPDATA%\TokenVault\Updates` |

To uninstall: delete those folders and `TokenVault.exe`. To also remove the sandbox's loopback
exemption, run `CheckNetIsolation LoopbackExempt -d -n=TokenVault.MinecraftSandbox` as administrator.

## Building from source

Requires the .NET 8 SDK or newer.

```powershell
dotnet build TokenVault.sln -c Release
dotnet run --project tests/TokenVault.Tests -c Release   # security regression suite
./scripts/Build.ps1                                       # tests + single-file exe in artifacts/TokenVault
```

| Project | Role |
|---|---|
| `TokenVault.App` | WPF window: library, Play, servers, security, settings |
| `TokenVault.Vault` | Microsoft sign-in, encrypted sign-in storage, local HTTPS API, server login broker |
| `TokenVault.Launcher` | Game installer, AppContainer sandbox, folder policy, Java truststore |
| `TokenVault.Packs` | Modpack and archive import |
| `TokenVault.Core` | Settings, Minecraft packet I/O and crypto, envelope encryption |

### Releasing

Push a tag such as `v1.1.0` and CI builds (with that version), tests and publishes a GitHub release.

**Update signing.** The public half of the release key is in `Directory.Build.props`, so every build can
verify updates. Store the private key as the repository **secret** `UPDATE_SIGNING_KEY`; the release job
then publishes a signed `TokenVault-update.json` next to the zip. Without the secret, releases still work
but installed copies only tell players about them. Anyone holding the private key can push code to every
installed copy: never commit or share it. To replace the key, run `pwsh scripts/New-UpdateSigningKey.ps1`
and update both the secret and `TokenVaultUpdatePublicKey` (players then download one release by hand).

**Usage statistics.** The PostHog *project* key (`phc_…`, public by design) is in `Directory.Build.props`
(`PostHogProjectKey`, with `PostHogHost` set to the US cloud; use `https://eu.i.posthog.com` for an EU
project). Never use a personal API key (`phx_…`): it is a secret, and the build refuses it. In PostHog,
turn on "Discard client IP data".

**Code signing.** To sign builds (which removes the "unknown publisher" warning), add two repository secrets:
`SIGNING_CERT_PFX_BASE64` (your code-signing certificate as base64) and `SIGNING_CERT_PASSWORD`.
Affordable options include an OV certificate from a CA, Microsoft's Azure Trusted Signing, or the free
SignPath Foundation programme for open-source projects. A new certificate still builds SmartScreen
reputation over the first downloads.

### Sign-in application ID

Microsoft sign-in needs a registered application ID. By default Token Vault uses the public ID that
Prism Launcher publishes, so Microsoft's consent page says "Prism Launcher". If you distribute your own
build, register your own app (personal Microsoft accounts, public client, redirect
`http://127.0.0.1:25597/`, Minecraft API approval) and set it under **Settings**.

## Documentation

* [CRYPTOGRAPHY.md](docs/CRYPTOGRAPHY.md): design, threat model, protocol analysis, verification
* [ALLOWLIST.md](docs/ALLOWLIST.md): exactly which account calls the game may make
* [ACCEPTANCE.md](docs/ACCEPTANCE.md): manual release checks
* [VALIDATION.md](docs/VALIDATION.md): what has been tested, and how

## License

MIT. Token Vault is not affiliated with Mojang or Microsoft. No Mojang, Microsoft, Fabric or JDK
binaries are included; they are downloaded from their publishers on first run.
