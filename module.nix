{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.vanta;

  # Binaries the agent expects at the hardcoded /var/vanta path. They must be
  # REAL files owned by root and not writable by non-root: metalauncher's
  # self-protection check refuses to launch anything it deems writable, and a
  # symlink's own mode is 0777 (lrwxrwxrwx), which that check reads as
  # world-writable. So we copy the store files in rather than symlink them.
  managedBins = [
    "metalauncher"
    "launcher"
    "vanta-cli"
    "osqueryd"
    "osquery-vanta.ext"
  ];

  # Materialize /var/vanta from the package. Guarded by a stamp holding the
  # package store path so the ~85MB osqueryd is only copied when the package
  # actually changes, not on every service start.
  materializeScript = ''
    install -d -m 0755 -o root -g root /var/vanta
    # metalauncher's pid file; it must exist for the sandbox to bind it.
    [ -e /run/metalauncher.pid ] || install -m 0644 -o root -g root /dev/null /run/metalauncher.pid
    stamp=/var/vanta/.package
    if [ "$(cat "$stamp" 2>/dev/null)" != "${cfg.package}" ]; then
      ${lib.concatMapStringsSep "\n" (f: ''
        rm -f "/var/vanta/${f}"
        install -m 0755 -o root -g root "${cfg.package}/libexec/vanta/${f}" "/var/vanta/${f}"
      '') managedBins}
      rm -f /var/vanta/cert.pem
      install -m 0644 -o root -g root "${cfg.package}/libexec/vanta/cert.pem" /var/vanta/cert.pem
      echo "${cfg.package}" > "$stamp"
    fi
  '';

  jq = lib.getExe pkgs.jq;
  # `trim` only exists from jq 1.8.
  trimmedKey = ''($key | gsub("^\\s+|\\s+$"; ""))'';

  # /etc/vanta.conf holds the secret AGENT_KEY, so it never enters the store.
  # With agentKeyFile set we compose it declaratively; otherwise we seed a
  # default (if absent) so the daemon starts and `vanta-cli register` can fill
  # it in -- without clobbering an already-registered config on restart.
  #
  # The key only ever reaches jq through --rawfile, so it stays out of argv
  # (and `ps`), and jq does the JSON escaping.
  configScript =
    if cfg.agentKeyFile != null then
      # The onboarding key enrolls via config activation (exactly what the
      # upstream .deb postinst does), NOT via `vanta-cli register`: writing
      # ACTIVATION_REQUESTED_NONCE alongside the key + owner email is what tells
      # the agent to activate. Only (re)write when the key actually changes, so
      # restarts don't reset the nonce or clobber post-activation state.
      ''
        keyFile=${lib.escapeShellArg cfg.agentKeyFile}
        if ! ${jq} -e --rawfile key "$keyFile" '${trimmedKey} != ""' -n >/dev/null; then
          echo "services.vanta: agentKeyFile $keyFile is missing or empty" >&2
          exit 1
        fi
        if ! ${jq} -e --rawfile key "$keyFile" '.AGENT_KEY == ${trimmedKey}' /etc/vanta.conf >/dev/null 2>&1; then
          tmp="$(mktemp /etc/.vanta.conf.XXXXXX)"
          trap 'rm -f "$tmp"' EXIT
          ${jq} -cn \
            --rawfile key "$keyFile" \
            --argjson nonce "$(date +%s000)" \
            --arg email ${lib.escapeShellArg cfg.ownerEmail} \
            --arg region ${lib.escapeShellArg (toString cfg.region)} \
            '{ACTIVATION_REQUESTED_NONCE: $nonce, AGENT_KEY: ${trimmedKey}, OWNER_EMAIL: $email, REGION: $region, NEEDS_OWNER: true}' \
            > "$tmp"
          chown root:root "$tmp"
          mv -f "$tmp" /etc/vanta.conf
        fi
      ''
    else
      ''
        if [ ! -e /etc/vanta.conf ]; then
          install -m 0600 -o root -g root /dev/null /etc/vanta.conf
          echo '{"AGENT_KEY":"","OWNER_EMAIL":"","NEEDS_OWNER":true}' > /etc/vanta.conf
        fi
      '';

  # Quote a path for systemd's path-list settings: spaces, quotes and
  # specifiers (%) would otherwise be split or expanded.
  unitPath = p: ''"${lib.replaceStrings [ "\\" "\"" "%" ] [ "\\\\" "\\\"" "%%" ] p}"'';
  optional = p: unitPath "-${p}";
in
{
  options.services.vanta = {
    enable = lib.mkEnableOption "the Vanta Device Monitor agent";

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.vanta-agent;
      defaultText = lib.literalExpression "pkgs.vanta-agent";
      description = "The vanta-agent package to run.";
    };

    agentKeyFile = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "/run/secrets/vanta-agent-key";
      description = ''
        Absolute path to a root-readable file containing the Vanta onboarding
        key (`VANTA_KEY`, from <https://app.vanta.com/onboarding>). Read at
        service start to compose {file}`/etc/vanta.conf` with an activation
        nonce, which is how the agent enrolls (the same mechanism the upstream
        .deb uses). Requires {option}`services.vanta.ownerEmail` and
        {option}`services.vanta.region`.

        This is a string, not a path, so the key never gets copied into the
        world-readable Nix store. Use agenix, sops-nix or a hand-placed
        root-only file.

        This key enrolls via config activation, not via
        `vanta-cli register --secret` (that path uses a different server
        mutation and rejects the onboarding key). When `null`,
        {file}`/etc/vanta.conf` is seeded with an empty default so you can
        enroll by other means.
      '';
    };

    sandbox = {
      enable = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = ''
          Make the whole filesystem read-only to the agent except
          {file}`/var/vanta`, {file}`/etc/vanta.conf` and its pid file, give
          it a private {file}`/tmp`, and drop root capabilities it doesn't
          need (module loading, ptrace, raw I/O, ...). `CAP_SYS_ADMIN` stays:
          the disk encryption check needs device-mapper ioctls, which require
          it, and with it a hostile agent could undo the sandbox. So this
          limits mistakes and what osquery reads through files, not a
          determined attacker. Files the agent reads are the real ones, but
          without ptrace osquery can't read the executable path, environment
          or open files/sockets of processes holding capabilities it lacks
          (most root-owned daemons, security tools included), so Vanta's
          process inventory is less complete; and
          {option}`services.vanta.sandbox.hideSystemSecrets` hides some files.
        '';
      };

      visiblePaths = lib.mkOption {
        type = lib.types.nullOr (lib.types.listOf lib.types.str);
        default = null;
        example = [ "/home/alice/work" ];
        description = ''
          If set, the agent sees the OS plus only these paths (read-only).
          {file}`/home`, {file}`/root`, {file}`/run/user` and {file}`/var/lib`
          become empty, {file}`/srv`, {file}`/mnt` and {file}`/media` become
          inaccessible (so entries can't be under those), and each listed path
          is bound back in. The rest of the
          system (/nix, /etc, /usr, /boot, /sys, /proc, /dev, /run, /var)
          stays visible. Requires {option}`services.vanta.sandbox.enable`.

          Like {option}`services.vanta.sandbox.hiddenPaths`, this changes what
          Vanta sees: checks on data outside these paths (SSH keys, browser
          extensions, ...) find nothing. It limits what osquery's file-based
          tables can read; it is not a hard boundary, since the agent is root
          and can still read raw block devices.
        '';
      };

      hideSystemSecrets = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = ''
          Hide system secrets that no Vanta check needs: Wi-Fi credentials
          (NetworkManager, including `ensureProfiles`, wpa_supplicant, iwd),
          SSH host private keys ({option}`services.openssh.hostKeys`), and
          sops-nix/agenix secrets under {file}`/run`. Secrets kept elsewhere
          (e.g. a sops age key file) need
          {option}`services.vanta.sandbox.hiddenPaths`.
          {file}`/etc/shadow` stays visible: osquery's `shadow` table could
          feed a password-policy check.
        '';
      };

      hiddenPaths = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [ ];
        example = [
          "/home/alice/.ssh"
          "/home/alice/.config/google-chrome"
        ];
        description = ''
          Absolute paths made inaccessible to the agent (systemd
          `InaccessiblePaths=`; no globs). A path is only hidden if it exists
          when the service starts; one created later stays visible until the
          next restart, and so does one deleted and recreated (or replaced by
          rename) on the host. Prefer hiding a stable parent directory.

          This changes what the agent reports: checks that rely on hidden data
          (SSH key encryption, browser password-manager extensions, ...) will
          see nothing there. The result in Vanta then no longer describes the
          real device, so only use this where your security team agrees.
        '';
      };
    };

    ownerEmail = lib.mkOption {
      type = lib.types.str;
      default = "";
      example = "alice@example.com";
      description = ''
        Email of the person this device belongs to, recorded in
        {file}`/etc/vanta.conf`. Required with
        {option}`services.vanta.agentKeyFile`.
      '';
    };

    region = lib.mkOption {
      type = lib.types.nullOr (
        lib.types.enum [
          "us"
          "eu"
          "aus"
        ]
      );
      default = null;
      example = "us";
      description = ''
        Region of your Vanta tenant, recorded in {file}`/etc/vanta.conf`.
        Required with {option}`services.vanta.agentKeyFile`. These are the
        values the agent itself accepts.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.agentKeyFile != null -> cfg.ownerEmail != "" && cfg.region != null;
        message = "services.vanta: ownerEmail and region must be set when agentKeyFile is provided.";
      }
      {
        assertion = lib.all (lib.hasPrefix "/") (
          cfg.sandbox.hiddenPaths ++ lib.optionals (cfg.sandbox.visiblePaths != null) cfg.sandbox.visiblePaths
        );
        message = "services.vanta: sandbox.hiddenPaths and sandbox.visiblePaths must be absolute paths.";
      }
      {
        # systemd drops binds beneath an InaccessiblePaths= entry.
        assertion =
          cfg.sandbox.visiblePaths != null
          -> !lib.any (
            p:
            lib.any (r: p == r || lib.hasPrefix "${r}/" p) [
              "/srv"
              "/mnt"
              "/media"
            ]
          ) cfg.sandbox.visiblePaths;
        message = "services.vanta: sandbox.visiblePaths can't be under /srv, /mnt or /media.";
      }
      {
        assertion = cfg.sandbox.visiblePaths != null -> cfg.sandbox.enable;
        message = "services.vanta: sandbox.visiblePaths requires sandbox.enable.";
      }
      {
        assertion =
          cfg.agentKeyFile != null
          -> lib.hasPrefix "/" cfg.agentKeyFile && !lib.hasPrefix builtins.storeDir cfg.agentKeyFile;
        message = "services.vanta: agentKeyFile must be an absolute path outside the Nix store (it holds a secret).";
      }
    ];

    # Copy the binaries into /var/vanta (as real, non-writable files) and
    # prepare /etc/vanta.conf and the pid file before the agent starts.
    # A separate, unsandboxed unit rather than ExecStartPre, which would run
    # under the agent's mount restrictions ("+" doesn't lift them all) and
    # couldn't write /etc. PartOf makes `systemctl restart vanta` rerun this.
    systemd.services.vanta-setup = {
      description = "Prepare /var/vanta and /etc/vanta.conf for the Vanta agent";
      partOf = [ "vanta.service" ];
      # Reruns with every (re)start of vanta.service, whose own start limit
      # already bounds restart loops.
      startLimitIntervalSec = 0;
      script = materializeScript + configScript;
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
      };
    };

    systemd.services.vanta = {
      description = "Vanta monitoring software";
      requires = [ "vanta-setup.service" ];
      after = [
        "network-online.target"
        "vanta-setup.service"
      ];
      wantedBy = [ "multi-user.target" ];

      serviceConfig = {
        ExecStart = "/var/vanta/metalauncher";
        Restart = "on-failure";
        KillMode = "control-group";
        KillSignal = "SIGTERM";
        TimeoutStartSec = 0;

        # Light sandboxing only. osquery reads most of the system, home
        # directories included (SSH keys, browser profiles), and the agent
        # rewrites /etc/vanta.conf and /var/vanta at runtime, so /etc, /var
        # and /home stay visible. It never uses setuid helpers. Nothing that
        # restricts devices either (DeviceAllow=, PrivateDevices=, and
        # ProtectClock=, which is documented to imply DeviceAllow=): osquery's
        # disk encryption table needs block and device-mapper devices.
        ProtectSystem = true; # /usr, /boot, /efi read-only
        ProtectHome = "read-only";
        NoNewPrivileges = true;
        RestrictRealtime = true;
        LockPersonality = true;
      }
      // lib.optionalAttrs cfg.sandbox.enable {
        # The agent writes its state, logs and update downloads under
        # /var/vanta, rewrites /etc/vanta.conf in place (os.WriteFile; it
        # never creates files next to it) and writes /var/run/metalauncher.pid
        # with os.OpenFile. On exit it tries to delete the pid file, which
        # fails and logs "could not remove pid file"; harmless (the next start
        # overwrites it), and cheaper than leaving all of /run writable.
        ProtectSystem = "strict";
        ReadOnlyPaths = [ "/run" ]; # strict leaves /run writable
        ReadWritePaths = [
          "/var/vanta"
          "/etc/vanta.conf"
          "/run/metalauncher.pid"
        ];
        PrivateTmp = true;
        # No device restrictions here (see above); these only hide kernel
        # interfaces osquery reads through /proc and /sys anyway.
        ProtectKernelModules = true;
        ProtectKernelTunables = true;
        ProtectKernelLogs = true;
        CapabilityBoundingSet = lib.concatStringsSep " " [
          "~CAP_SYS_MODULE"
          "CAP_SYS_PTRACE"
          "CAP_SYS_RAWIO"
          "CAP_SYS_BOOT"
          "CAP_SYS_TIME"
          "CAP_WAKE_ALARM"
          "CAP_SYS_PACCT"
          "CAP_MKNOD"
          "CAP_LINUX_IMMUTABLE"
          "CAP_SETFCAP"
          "CAP_MAC_ADMIN"
          "CAP_MAC_OVERRIDE"
          "CAP_BPF"
          "CAP_PERFMON"
          "CAP_SYSLOG"
        ];
      }
      // lib.optionalAttrs (cfg.sandbox.visiblePaths != null) {
        # tmpfs over /home, /root and /run/user; visiblePaths are bound back.
        ProtectHome = "tmpfs";
        TemporaryFileSystem = "/var/lib:ro";
        BindReadOnlyPaths = map optional cfg.sandbox.visiblePaths;
      }
      // {
        InaccessiblePaths =
          map optional cfg.sandbox.hiddenPaths
          ++ lib.optionals (cfg.sandbox.enable && cfg.sandbox.hideSystemSecrets) (
            map optional (
              [
                "/etc/NetworkManager/system-connections"
                "/run/NetworkManager/system-connections" # ensureProfiles
                "/etc/wpa_supplicant.conf"
                "/etc/wpa_supplicant/imperative.conf"
                "/var/lib/iwd"
                "/run/secrets"
                "/run/secrets.d"
                "/run/secrets-for-users"
                "/run/agenix"
                "/run/agenix.d"
              ]
              ++ map (k: k.path) config.services.openssh.hostKeys
            )
          )
          ++ lib.optionals (cfg.sandbox.visiblePaths != null) [
            "-/srv"
            "-/mnt"
            "-/media"
          ];
      };
    };
  };
}
