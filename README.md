# vanta-nix

The [Vanta Device Monitor](https://vanta.com) agent, packaged for NixOS as a flake
exposing a package (`vanta-agent`) and a NixOS module (`services.vanta`).

Derived from [AustinMroz/VantaDeviceManager](https://github.com/AustinMroz/VantaDeviceManager)
(initial packaging by Austin Mroz); this repo continues it with a fresh history.
The agent is proprietary. This repository contains Nix code only; the `.deb` is
downloaded from Vanta at build time.

## Install

```nix
{
  inputs.vanta.url = "github:synap5e/vanta-nix";

  outputs = { self, nixpkgs, vanta, ... }: {
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        vanta.nixosModules.vanta
        {
          nixpkgs.config.allowUnfreePredicate =
            pkg: nixpkgs.lib.getName pkg == "vanta-agent";

          services.vanta = {
            enable = true;
            agentKeyFile = "/run/secrets/vanta-agent-key"; # see Enrollment
            ownerEmail = "you@example.com";
            region = "us"; # "us", "eu" or "aus": your Vanta tenant's region
          };
        }
      ];
    };
  };
}
```

The module sets `nixpkgs.overlays`, so it can't be combined with a read-only
`pkgs` (`nixpkgs.pkgs`). In that case import `module.nix` directly and add
`overlays.default` to your own `pkgs`.

## Enrollment

`agentKeyFile` points at a file holding the onboarding key (`VANTA_KEY` from
<https://app.vanta.com/onboarding>). It must be an absolute path **outside the Nix
store**: use agenix, sops-nix, or a file you place by hand
(`install -m 600 /dev/null /etc/vanta-key` and then write the key into it).

On service start the module writes `/etc/vanta.conf` (mode 0600) with the key, owner
email, region and an activation nonce, which is what the upstream `.deb`'s postinst
does. The agent activates from that on its next run. The config is only rewritten
when the key in the file differs from the key in `/etc/vanta.conf`, so restarts don't
reset activation. To re-enroll with the same key (for example after changing
`ownerEmail` or `region`), delete `/etc/vanta.conf` and restart `vanta.service`.

The key never appears on a command line: the module reads it with
`jq --rawfile`.

Without `agentKeyFile`, the module seeds an empty `/etc/vanta.conf` and the agent runs
unregistered until you enroll some other way.

## Verify

```
systemctl status vanta
sudo /var/vanta/vanta-cli check-registration
sudo /var/vanta/vanta-cli status
journalctl -u vanta
```

The device should appear under the owner's account in Vanta within a few minutes.

## How it runs

The agent hardcodes `/var/vanta`, and its `metalauncher` refuses to start anything
it considers writable by non-root. Store symlinks count as writable (mode 0777),
so on each start the service copies the binaries into `/var/vanta` as real,
root-owned 0755 files. A stamp file (`/var/vanta/.package`) records the package
path, so the copy only happens when the package changes.

`osqueryd` is the only dynamically linked binary. The package patchelfs it against
Nix's glibc, so `programs.nix-ld` is not needed.

### Sandboxing

The agent runs as root and has to read most of the system. The unit always sets
`ProtectHome=read-only`, `NoNewPrivileges` and a few cheap restrictions. It never
restricts devices, because osquery needs block devices for disk encryption.

`services.vanta.sandbox.enable` (default `true`) adds a filesystem sandbox through
systemd's mount namespacing:

- Everything is read-only to the agent except `/var/vanta`, `/etc/vanta.conf` and
  `/run/metalauncher.pid`, and `/tmp` is private. metalauncher can't delete its
  pid file on exit, so it logs "could not remove pid file"; that's harmless.
- Root capabilities it doesn't need are dropped: module loading, `ptrace`, raw
  I/O, clock, MAC admin, BPF and others. Kernel modules, tunables and logs are
  protected. Without `ptrace`, osquery can't read the executable path,
  environment or open files and sockets of processes that hold capabilities the
  agent lacks. That covers most root-owned daemons, security tools included, so
  Vanta's process inventory is less complete, and a check that looks for a
  running security tool by path may see less. This is a deliberate trade-off.
- `CAP_SYS_ADMIN` stays, because the disk-encryption check needs device-mapper
  ioctls and those require it. With it, a hostile agent could undo the sandbox.
  The sandbox limits mistakes and what osquery reads through files; it doesn't
  contain a determined attacker.
- `sandbox.hideSystemSecrets` (default `true`) hides:
  - Wi-Fi credentials from NetworkManager (including `ensureProfiles`),
    wpa_supplicant and iwd;
  - SSH host private keys (from `services.openssh.hostKeys`);
  - sops-nix and agenix secrets under `/run`.

  No check I found needs these. It doesn't cover secrets kept anywhere else (for
  example a sops age key file); add those to `hiddenPaths`. `/etc/shadow` stays
  visible, since osquery's `shadow` table could feed a password-policy check.
- Apart from the hidden secrets and the process details above, the agent reads
  the real system; it just can't modify it.
- Setup (copying binaries, writing the config) runs in a separate unsandboxed
  unit, `vanta-setup.service`, before the agent starts.

`services.vanta.sandbox.visiblePaths` goes further: the agent sees the OS plus
only the listed directories, read-only.

```nix
services.vanta.sandbox.visiblePaths = [ "/home/alice/work" ];
```

- `/home`, `/root`, `/run/user` (session sockets) and `/var/lib` become empty.
- `/srv`, `/mnt` and `/media` become inaccessible.
- `/nix`, `/etc`, `/usr`, `/boot`, `/sys`, `/proc`, `/dev`, `/run` and the rest
  of `/var` stay visible.

This limits what osquery's file-based tables (SSH keys, browser extensions, file
hashes, carving) can read. It isn't a hard boundary: the agent is root and can
still open raw block devices, which the disk-encryption check needs.

`services.vanta.sandbox.hiddenPaths` makes listed paths inaccessible to the agent:

```nix
services.vanta.sandbox.hiddenPaths = [ "/home/alice/.ssh" ];
```

**Both options change what Vanta sees.** A check that relies on hidden data (SSH key
encryption, password-manager browser extensions, …) finds nothing, so the result
in Vanta no longer describes the real device. Only hide paths if your security
team agrees. Paths must be absolute and globs aren't supported. A path is only
hidden if it exists when the service starts. One created later stays visible until
the next restart, and so does one that's deleted and recreated (or replaced by
rename) on the host, so prefer hiding a stable parent directory.

Network access isn't restricted. Vanta's endpoints sit behind CDNs with changing
IPs, so an IP allowlist (`IPAddressAllow=`) isn't practical.

### Autoupdate

The `launcher` has a built-in updater. It polls Vanta's TUF repository
(`agent-downloads.vanta.com`), downloads a newer `.deb`/`.rpm` and installs it with
`systemd-run dpkg …`/`rpm …`. Before doing any of that it looks up `dpkg` and `rpm`
on `PATH`. The service's `PATH` on NixOS contains neither, so the update stops with
"no supported package manager installed" and the agent stays on the pinned version.
(It may report that failure to Vanta's telemetry each cycle.) The agent has no
setting to turn the updater off. Don't add `dpkg` or `rpm` to
`systemd.services.vanta.path`: an update would then overwrite `/var/vanta` with an
unpatched `osqueryd`, and the stamp wouldn't notice.

So updates come only from bumping the pin (below) and rebuilding. Vanta may flag
the device as running an outdated agent if the pin falls far behind.

## Updating the pin

`package.nix` fetches a versioned URL from Vanta's update repository,
`https://agent-downloads.vanta.com/targets/versions/<version>/vanta-amd64.deb`.
Old versions stay there (the repository's `targets.json` lists every release since
2.0.0), so a pinned build keeps working after new releases and a rollback can
still re-fetch.

To bump:

```
# Which version does Vanta currently serve as "latest"?
curl -sI https://app.vanta.com/osquery/download/linux | grep -i '^location'

nix store prefetch-file \
  https://agent-downloads.vanta.com/targets/versions/<version>/vanta-amd64.deb
```

Put the version and the reported `hash` into `package.nix`, then
`nix build .#vanta-agent` and `nix flake check`.

## Uninstall

Setting `services.vanta.enable = false` stops and removes the service. It leaves the
agent's state in place:

- `/var/vanta`: binaries, osquery database, logs, update metadata
- `/etc/vanta.conf`: contains the agent key

The upstream `.deb` deletes `/var/vanta` on removal (and leaves `/etc/vanta.conf`). To do
the same after switching:

```
sudo rm -rf /var/vanta /etc/vanta.conf
```

Remove the device in Vanta's web UI as well, since the agent doesn't deregister itself.

## Development

```
nix build .#vanta-agent
nix flake check        # includes a NixOS VM test (needs KVM)
nix fmt -- *.nix tests/*.nix
```

The flake's own outputs allow the `vanta-agent` unfree package, so no
`NIXPKGS_ALLOW_UNFREE` is needed here. The VM test has no network access and never
contacts Vanta. It covers what the module controls (the `/var/vanta` copy and the
config generation), not enrollment.

## Compatibility with NixOS and non-GNOME desktops

These findings come from static inspection of agent 2.20.0 (strings and
disassembly). The agent was never run against Vanta. The main finding is that the
**Linux checks aren't in the package**. The launcher runs `osqueryd` with Vanta's
TLS config, logger and distributed-query plugins, so the SQL behind each check comes
from Vanta's servers at runtime. Verdicts marked *inferred* follow from which osquery
tables exist, not from the actual queries.

| Check | Mechanism found | NixOS + niri, likely result |
|---|---|---|
| Disk encryption | osquery `disk_encryption`, libcryptsetup statically linked | **Pass** if `/` is on LUKS (*inferred*) |
| Screen lock | Only a macOS implementation (`launchctl` → `screenlock` table). No `gsettings`, dconf or KDE code, and no dconf osquery table | **Unknown**; probably not evaluable on Linux |
| OS updates | Only `deb_packages`/`rpm_packages`/`apt_sources`/`yum_sources` and `os_version`; nothing for apt or unattended-upgrades | **Likely fail or "unsupported"** (*inferred*) |
| Password manager | No dedicated code; `chrome_extensions`/`firefox_addons` tables read standard profile paths in `/home` | **Unknown**; a real extension in a standard Chrome/Firefox profile is the plausible signal |
| Antivirus | No dedicated code; generic `processes`/package tables | **Unknown**, probably fail without real AV |
| SSH keys | The extension runs `select uid, path, encrypted from user_ssh_keys …` | **Fails for passphraseless keys**, which is accurate |
| SSH keys in the TPM (`ssh-tpm-agent`) | Their `.tpm` files (`TSS2 PRIVATE KEY`) aren't recognised by `user_ssh_keys`; tested in a VM with a software TPM | **Not listed**, which is accurate: no exportable private key is on disk. The PIN is enforced by the TPM, not visible to Vanta |

Making the result reflect the real state:

- Use a real passphrase on SSH keys, and install a real password manager's browser
  extension in a standard profile directory.
- Setting `org.gnome.desktop.screensaver` keys to mirror a real swayidle/hypridle
  config is harmless and truthful. Nothing in this agent version reads them, so
  don't count it as meeting the screen-lock check.
- **Don't fake state.** That includes writing `/etc/debian_version`, a fake
  `/etc/os-release`, dpkg/rpm databases, dummy AV or password-manager binaries, or
  hiding SSH keys from the agent. Any of these would spoof a compliance check.

Agent behaviour on NixOS:

- The agent only executes binaries under `/usr/bin`, `/usr/sbin`, `/bin`, `/sbin`
  or `/var/vanta` that are root-owned and not group- or world-writable. NixOS has
  no `systemctl` or `lsb_release` at those paths, so the agent's self-restart
  (after a region change or update) and `vanta-cli start`/`stop`/`uninstall` fail.
  Manage the agent with `systemctl … vanta` instead. Setting `region` correctly
  avoids the region-change restart.
- The Linux build has no GUI or tray component, so niri/noctalia are irrelevant
  to it.

## Limitations

- x86_64-linux only. Vanta publishes arm64 `.deb`s too, but they aren't packaged
  or tested here.
- The agent doesn't autoupdate (see above).
- Not tested against a live Vanta tenant from this repo: enrollment uses the
  mechanism upstream reported working, unchanged except for how the JSON is built.
- The sandbox was tested in a VM with an unregistered agent, not against a live
  tenant. If a future agent version writes somewhere new, it shows up as
  "read-only file system" errors in `journalctl -u vanta`. Set
  `sandbox.enable = false` to rule the sandbox out.

## License

All Nix code and documentation in this repository is MIT-licensed (see `LICENSE`),
including the code derived from upstream.

The Vanta agent is proprietary (`meta.license = unfree`) and isn't redistributed
here.
