# Checks what the module controls: the /var/vanta copy, /etc/vanta.conf
# generation, and that the unit's sandboxing still lets the agent start
# osqueryd. Test VMs have no route out, so the agent cannot reach Vanta and
# nothing is ever enrolled.
{ lib, ... }:
let
  # Quote, backslash and trailing newline: exercises JSON escaping and trimming.
  key = ''fake"key\one'';
in
{
  name = "vanta";

  nodes = {
    plain =
      { pkgs, ... }:
      {
        imports = [ ../module.nix ];
        services.vanta = {
          enable = true;
          sandbox.visiblePaths = [ "/home/alice/work dir" ];
        };
        users.users.alice.isNormalUser = true;
        environment.systemPackages = [ pkgs.bpftools ];
      };

    enrolled = {
      imports = [ ../module.nix ];
      services.vanta = {
        enable = true;
        agentKeyFile = "/root/vanta-key";
        ownerEmail = "test@example.com";
        region = "us";
        sandbox.hiddenPaths = [
          "/root/hidden"
          "/does/not/exist"
        ];
      };
      # Not started at boot, so the test can place the key first.
      systemd.services.vanta.wantedBy = lib.mkForce [ ];
    };
  };

  testScript = ''
    import json
    import shlex

    key = ${builtins.toJSON key}

    def conf(m):
        return json.loads(m.succeed("cat /etc/vanta.conf"))

    def in_unit(m, cmd):
        """Run cmd in the agent's mount namespace (what the agent sees)."""
        pid = m.succeed("systemctl show -p MainPID --value vanta").strip()
        return f"nsenter -t {pid} -m -- sh -c {shlex.quote(cmd)}"

    def start(m):
        m.succeed("systemctl reset-failed vanta || true")
        m.succeed("systemctl restart vanta")

    start_all()

    with subtest("binaries are real root-owned files"):
        plain.wait_until_succeeds("test -e /var/vanta/.package")
        for f in ["metalauncher", "launcher", "vanta-cli", "osqueryd", "osquery-vanta.ext"]:
            plain.succeed(f"test -f /var/vanta/{f} -a ! -L /var/vanta/{f}")
            assert plain.succeed(f"stat -c '%U:%G %a' /var/vanta/{f}").strip() == "root:root 755"
        plain.succeed("/var/vanta/osqueryd --version")

    with subtest("agent starts osqueryd under the unit's sandboxing"):
        plain.wait_until_succeeds("pgrep -x osqueryd", timeout=300)

    with subtest("sandbox: read-only system except the agent's own paths"):
        plain.succeed(in_unit(plain, "! touch /etc/probe"))
        plain.succeed(in_unit(plain, "! touch /root/probe"))
        plain.succeed(in_unit(plain, "touch /var/vanta/probe && rm /var/vanta/probe"))
        plain.succeed(in_unit(plain, "test -w /etc/vanta.conf && cat /etc/os-release"))
        plain.succeed("sleep 10")
        plain.fail(
            "journalctl -u vanta | grep -v 'could not remove pid file'"
            " | grep -i 'read-only file system'"
        )

    with subtest("sandbox: only the OS and visiblePaths"):
        plain.succeed(
            "install -d -o alice '/home/alice/work dir' /home/alice/private /var/lib/secret",
            "echo w > '/home/alice/work dir/f'; echo p > /home/alice/private/f",
            "echo s > /var/lib/secret/f; echo r > /root/f; mkdir -p /run/user/1000",
            "install -d /etc/NetworkManager/system-connections /run/secrets",
            "echo psk > /etc/NetworkManager/system-connections/wifi; echo k > /run/secrets/s",
        )
        start(plain)  # bind mounts are set up at start
        plain.succeed(in_unit(plain, "cat '/home/alice/work dir/f' /etc/os-release"))
        for f in ["/home/alice/private/f", "/var/lib/secret/f", "/root/f", "/run/user/1000"]:
            plain.succeed(in_unit(plain, f"! ls {f}"))
        plain.succeed(in_unit(plain, "! touch '/home/alice/work dir/probe'"))
        plain.succeed(in_unit(plain, "touch /var/vanta/probe && rm /var/vanta/probe"))
        plain.wait_until_succeeds("pgrep -x osqueryd", timeout=300)
        plain.succeed("sleep 10")
        # Known and harmless: metalauncher can't delete its bound pid file on exit.
        plain.fail(
            "journalctl -u vanta | grep -v 'could not remove pid file'"
            " | grep -iE 'read-only file system|permission denied'"
        )

    with subtest("sandbox: capabilities, /run, system secrets, devices"):
        pid = plain.succeed("systemctl show -p MainPID --value vanta").strip()
        bnd = int(plain.succeed(f"awk '/^CapBnd/ {{print $2}}' /proc/{pid}/status"), 16)
        # CAP_SYS_MODULE=16, CAP_SYS_RAWIO=17, CAP_SYS_PTRACE=19, CAP_SYS_ADMIN=21
        assert not bnd & (1 << 16 | 1 << 17 | 1 << 19), hex(bnd)
        assert bnd & (1 << 21), "CAP_SYS_ADMIN is needed for device-mapper ioctls"
        plain.succeed(in_unit(plain, "! touch /run/probe"))
        assert plain.succeed(in_unit(plain, "cat /run/metalauncher.pid")).strip() != ""
        for f in ["/etc/NetworkManager/system-connections/wifi", "/run/secrets/s"]:
            plain.succeed(in_unit(plain, f"! cat {f}"))
        plain.succeed(in_unit(plain, "test -r /etc/shadow"))
        # A device filter (cgroup_device BPF program) would hide disks from
        # osquery's disk_encryption table.
        progs = plain.succeed("bpftool cgroup show /sys/fs/cgroup/system.slice/vanta.service")
        assert "cgroup_device" not in progs, progs

    with subtest("unenrolled default conf"):
        assert plain.succeed("stat -c '%U %a' /etc/vanta.conf").strip() == "root 600"
        assert conf(plain)["AGENT_KEY"] == ""

    with subtest("unenrolled restart keeps an existing conf"):
        plain.succeed("""echo '{"AGENT_KEY":"registered"}' > /etc/vanta.conf""")
        start(plain)
        assert conf(plain)["AGENT_KEY"] == "registered"

    with subtest("missing key file fails the start"):
        enrolled.wait_for_unit("multi-user.target")
        enrolled.fail("systemctl start vanta")

    with subtest("blank key file fails the start"):
        enrolled.succeed("printf ' \\n' > /root/vanta-key")
        enrolled.succeed("systemctl reset-failed vanta || true")
        enrolled.fail("systemctl start vanta")
        enrolled.fail("test -e /etc/vanta.conf")

    with subtest("enrollment conf"):
        enrolled.succeed("install -m 600 /dev/null /root/vanta-key")
        enrolled.succeed(f"printf '%s\\n' {shlex.quote(key)} > /root/vanta-key")
        start(enrolled)
        c = conf(enrolled)
        assert c["AGENT_KEY"] == key, c
        assert c["OWNER_EMAIL"] == "test@example.com" and c["REGION"] == "us", c
        assert type(c["ACTIVATION_REQUESTED_NONCE"]) is int and c["NEEDS_OWNER"] is True, c
        assert enrolled.succeed("stat -c '%U %a' /etc/vanta.conf").strip() == "root 600"

    with subtest("offline: the agent stays up and keeps the activation request"):
        # No network in test VMs. The agent doesn't exit (so Restart= isn't
        # what carries enrollment over a late network); it keeps running.
        enrolled.succeed("sleep 45")
        enrolled.succeed("systemctl is-active vanta")
        assert enrolled.succeed("systemctl show -p NRestarts --value vanta").strip() == "0"
        assert "ACTIVATION_REQUESTED_NONCE" in conf(enrolled), conf(enrolled)
        print("AGENTLOG", enrolled.succeed(
            "grep -hiE 'activat|regist|retry|dial|lookup|no such host|unreachable' /var/vanta/log/* | cut -c1-300 | sort | uniq -c | sort -rn | head -20 || true"
        ))

    with subtest("sandbox: hidden paths"):
        enrolled.succeed("mkdir -p /root/hidden && echo secret > /root/hidden/f")
        start(enrolled)  # hiding applies to paths that exist at start
        enrolled.succeed(in_unit(enrolled, "! cat /root/hidden/f"))
        enrolled.succeed(in_unit(enrolled, "cat /etc/os-release"))

    with subtest("restart keeps the nonce"):
        nonce = c["ACTIVATION_REQUESTED_NONCE"]
        enrolled.succeed("sleep 1")
        start(enrolled)
        assert conf(enrolled)["ACTIVATION_REQUESTED_NONCE"] == nonce

    with subtest("key change re-enrolls"):
        enrolled.succeed("echo other-key > /root/vanta-key")
        start(enrolled)
        c = conf(enrolled)
        assert c["AGENT_KEY"] == "other-key" and c["ACTIVATION_REQUESTED_NONCE"] != nonce, c
  '';
}
