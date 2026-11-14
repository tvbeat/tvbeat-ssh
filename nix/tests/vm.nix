{ pkgs, self }:
let
  inherit (pkgs) lib;

  # vault is BUSL licensed (unfree in nixpkgs); only the test needs it
  vault = (import pkgs.path {
    inherit (pkgs.stdenv.hostPlatform) system;
    config.allowUnfreePredicate = p: lib.getName p == "vault-bin";
  }).vault-bin;

  issuer = "http://idp:5556";
  certTTL = 120; # short, so the test can watch a certificate expire

  dexConfig = pkgs.writeText "dex.yaml" (
    builtins.replaceStrings [ "@ISSUER@" "@LISTEN@" ] [ issuer "0.0.0.0:5556" ]
      (builtins.readFile ./dex.yaml.in)
  );

  site = pkgs.writeText "site.json" (builtins.toJSON {
    vault_addr = "http://idp:8200";
    sso = {
      inherit issuer;
      scopes = "openid email profile groups"; # dex only sends groups when asked
      browser.id = "tvbeat-auth-desktop";
      device.id = "tvbeat-auth-device";
      ssh_roles = { all = "sso-all"; devops = "sso-devops"; };
    };
    push_token_ttl = "2h";
    clusters = [{
      name = "dev0-hetz";
      jump = "jump.dev0-hetz.tvbeat.com:443";
      node_suffix = ".node";
      push_vault_token = true;
    }];
  });

  # what tvbeat-ssh 1.x users have today: vault's own OIDC flow on the
  # existing mount, the existing ssh roles
  siteLegacy = pkgs.writeText "site-legacy.json" (builtins.toJSON {
    vault_addr = "http://idp:8200";
    auth_mount = "oidc";
    browser_role = "default";
    callback_port = 8250;
    clusters = [{ name = "dev0-hetz"; jump = "jump.dev0-hetz.tvbeat.com:443"; node_suffix = ".node"; }];
  });

  testScripts = pkgs.runCommand "tvbeat-test-scripts" { } ''
    mkdir -p $out/bin
    cp ${./fake-browser.sh} $out/bin/fake-browser
    cp ${./approve-device.sh} $out/bin/approve-device
    chmod +x $out/bin/*
    patchShebangs $out/bin
  '';

  # accounts on the servers: linux username -> certificate principals (as
  # tvbeat/idm sets them up: the person's email)
  people = {
    alice = [ "alice@tvbeat.com" ];
    bob = [ "bob@tvbeat.com" ];
    mallory = [ "mallory@tvbeat.com" ];
    cjones = [ "carol.jones@tvbeat.com" ];
    dave = [ "dave@tvbeat.com" ];
  };

  # accounts on the laptop
  laptopUsers = [ "alice" "bob" "mallory" "carol" "dave" ];

  sshServer = port: { ... }: {
    services.openssh = {
      enable = true;
      ports = [ port ];
      settings = {
        PasswordAuthentication = false;
        KbdInteractiveAuthentication = false;
        PermitRootLogin = "prohibit-password";
        TrustedUserCAKeys = "/etc/ssh/user_ca.pub";
        LogLevel = "VERBOSE";
      };
      extraConfig = ''
        HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub
      '';
    };
    networking.firewall.allowedTCPPorts = [ port ];
    users.users = lib.mapAttrs (_: principals: {
      isNormalUser = true;
      openssh.authorizedPrincipals = principals;
    }) people // {
      root.openssh.authorizedPrincipals = [ "devops" ];
    };
  };
in
pkgs.testers.runNixOSTest {
  name = "tvbeat-auth";

  nodes = {
    idp = { ... }: {
      networking.firewall.allowedTCPPorts = [ 5556 8200 ];
      environment.systemPackages = [ vault pkgs.jq pkgs.curl ];
      environment.variables = { VAULT_ADDR = "http://127.0.0.1:8200"; VAULT_TOKEN = "root"; };
      virtualisation.memorySize = 1536;

      systemd.services.vault-dev = {
        wantedBy = [ "multi-user.target" ];
        after = [ "network.target" ];
        environment.HOME = "/run/vault-dev";
        serviceConfig = {
          ExecStart = "${vault}/bin/vault server -dev -dev-root-token-id=root -dev-listen-address=0.0.0.0:8200";
          DynamicUser = true;
          RuntimeDirectory = "vault-dev";
        };
      };
      systemd.services.dex = {
        wantedBy = [ "multi-user.target" ];
        after = [ "network.target" ];
        serviceConfig = {
          ExecStart = "${pkgs.dex-oidc}/bin/dex serve ${dexConfig}";
          DynamicUser = true;
        };
      };
    };

    jump = { nodes, ... }: {
      imports = [ (sshServer 443) ];
      networking.extraHosts = "${nodes.scoria.networking.primaryIPAddress} scoria.node";
    };

    scoria = { ... }: {
      imports = [ (sshServer 22) self.nixosModules.default ];
      # what a server gets: vault-login and the vault token helper
      programs.tvbeat-auth = {
        enable = true;
        package = pkgs.tvbeat-auth;
        inherit site;
      };
      environment.systemPackages = [ vault pkgs.curl pkgs.tmux ];
      environment.variables.VAULT_ADDR = "http://idp:8200";
    };

    client = { nodes, ... }: {
      environment.systemPackages = [ pkgs.tvbeat-auth pkgs.curl pkgs.jq testScripts ];
      environment.etc."tvbeat-test/site.json".source = site;
      environment.etc."tvbeat-test/site-legacy.json".source = siteLegacy;
      # what `tvbeat-ssh config --username dave` (1.x) left behind
      environment.etc."tvbeat-test/1x/tvbeat.conf".source = ./tvbeat-ssh-1x.conf;
      environment.etc."tvbeat-test/1x/config".text = ''
        # tvbeat configuration added by `tvbeat-ssh config` command
        Include tvbeat.conf

        Host *
          StrictHostKeyChecking accept-new
      '';
      networking.extraHosts = "${nodes.jump.networking.primaryIPAddress} jump.dev0-hetz.tvbeat.com";
      users.users = lib.genAttrs laptopUsers (_: { isNormalUser = true; });
    };
  };

  testScript = ''
    import shlex

    SSH = "ssh -o BatchMode=yes"
    SITE = "/etc/tvbeat-test/site.json"
    LEGACY_SITE = "/etc/tvbeat-test/site-legacy.json"

    # laptop account -> google account
    LOGINS = {"carol": "carol.jones@tvbeat.com"}

    def login_of(user):
        return LOGINS.get(user, f"{user}@tvbeat.com")

    def env(user, extra=""):
        return (
            f"export SSH_AUTH_SOCK=/tmp/{user}-agent.sock"
            f" TVBEAT_AUTH_BROWSER=fake-browser FAKE_LOGIN={login_of(user)} FAKE_PASSWORD=password"
            f" FAKE_BROWSER_LOG=/tmp/{user}-browser.log {extra}; "
        )

    def run(user, cmd, extra="", machine=None, expect_fail=False):
        m = machine or client
        full = "su - " + user + " -c " + shlex.quote(env(user, extra) + cmd)
        if expect_fail:
            return m.fail(full)
        return m.succeed(full)

    def browser_count(user):
        return int(client.succeed(f"grep -c done /tmp/{user}-browser.log 2>/dev/null || true").strip() or 0)

    def approve_code(code, user):
        """the person on their phone: approve the code in dex"""
        client.succeed(f"FAKE_LOGIN={login_of(user)} FAKE_PASSWORD=password approve-device ${issuer} {code}")

    def approve_pending(machine, errfile, user):
        try:
            machine.wait_until_succeeds(f"grep -A2 'enter the code' {errfile} | tail -1 | grep -E '[A-Z]{{4}}-[A-Z]{{4}}'", timeout=120)
        except Exception:
            print(machine.execute(f"ls -la /tmp; cat {errfile} {errfile.replace('.err', '.rc')}")[1])
            raise
        approve_code(machine.succeed(f"grep -A2 'enter the code' {errfile} | tail -1").strip(), user)

    def tmux(user, args):
        return scoria.succeed(f"su - {user} -c {shlex.quote('tmux ' + args)}")

    def in_pane(user, session, cmd):
        """type a command into a tmux session, as the person would"""
        tmux(user, f"send-keys -t {session} {shlex.quote(cmd)} Enter")

    def lookup_ok(machine, token_file):
        return f"curl -fsS -H \"X-Vault-Token: $(cat {token_file})\" http://idp:8200/v1/auth/token/lookup-self"

    start_all()

    with subtest("vault and dex come up and vault is configured like production"):
        idp.wait_for_unit("vault-dev.service")
        idp.wait_for_unit("dex.service")
        idp.wait_until_succeeds("curl -fs http://127.0.0.1:8200/v1/sys/health")
        idp.wait_until_succeeds("curl -fs ${issuer}/.well-known/openid-configuration")
        idp.succeed(
            "ISSUER=${issuer} BROWSER_CLIENT_ID=vault BROWSER_CLIENT_SECRET=vault-secret"
            " DESKTOP_CLIENT_ID=tvbeat-auth-desktop DEVICE_CLIENT_ID=tvbeat-auth-device"
            " CERT_TTL=${toString certTTL} bash ${./vault-setup.sh}"
        )

    with subtest("hosts get certificates from the host CA at deploy time"):
        user_ca = idp.succeed("vault read -field=public_key ssh/config/ca").strip()
        for m, principals in [
            (jump, "jump.dev0-hetz.tvbeat.com,dev0-hetz"),
            (scoria, "scoria.dev0-hetz,dev0-hetz+scoria.node"),
        ]:
            m.wait_for_unit("sshd.service")
            pub = m.succeed("cat /etc/ssh/ssh_host_ed25519_key.pub").strip()
            cert = idp.succeed(
                f"vault write -field=signed_key ssh-host/sign/hosts cert_type=host public_key={shlex.quote(pub)} valid_principals={principals}"
            ).strip()
            m.succeed(f"echo {shlex.quote(cert)} > /etc/ssh/ssh_host_ed25519_key-cert.pub")
            m.succeed(f"echo {shlex.quote(user_ca)} > /etc/ssh/user_ca.pub")
            m.succeed("systemctl restart sshd.service")
            m.wait_for_open_port(443 if m == jump else 22)

    client.wait_for_unit("multi-user.target")
    for u in ["alice", "bob", "mallory", "carol", "dave"]:
        run(u, f"ssh-agent -a /tmp/{u}-agent.sock > /dev/null")

    with subtest("setup signs in once, finds the linux username, writes ssh config and a CA-only known_hosts"):
        out = run("alice", f"tvbeat-auth setup --login browser --site {SITE}")
        assert "no fingerprint prompts" in out, out
        assert "All set, alice." in out, out
        assert browser_count("alice") == 1
        run("alice", "grep -qx '  User alice' ~/.ssh/tvbeat/config")
        run("alice", "grep -qx 'Include ~/.ssh/tvbeat/config' ~/.ssh/config")
        run("alice", "grep -q '^@cert-authority .*dev0-hetz' ~/.ssh/tvbeat/known_hosts")
        # idempotent, and no second sign-in
        run("alice", f"tvbeat-auth setup --site {SITE}")
        assert run("alice", "grep -c tvbeat/config ~/.ssh/config").strip() == "1"
        assert browser_count("alice") == 1
        run("alice", "tvbeat-auth check-host scoria.dev0-hetz")
        run("alice", "tvbeat-auth check-host dev0-hetz+scoria.node")
        run("alice", "tvbeat-auth check-host github.com", expect_fail=True)

    with subtest("a username that differs from the email comes from the account, not a guess"):
        out = run("carol", f"tvbeat-auth setup --login browser --site {SITE}")
        assert "All set, cjones." in out, out
        run("carol", "grep -qx '  User cjones' ~/.ssh/tvbeat/config")
        out = run("carol", f"{SSH} scoria.dev0-hetz 'id -un'")
        assert out.strip() == "cjones", out
        assert browser_count("carol") == 1

    with subtest("first ssh needs no further sign-in, and no host key prompt"):
        out = run("alice", f"{SSH} scoria.dev0-hetz 'id -un; hostname'")
        assert out.split() == ["alice", "scoria"], out
        assert browser_count("alice") == 1
        out = run("alice", "ssh-add -l")
        assert "tvbeat-auth role=all (ED25519-CERT)" in out, out
        run("alice", "test ! -e ~/.ssh/tvbeat/id_ed25519")  # key only in the agent

    with subtest("later connections need no sign-in; all spellings and the jump host work"):
        run("alice", f"{SSH} scoria.dev0-hetz true")
        run("alice", f"{SSH} dev0-hetz+scoria.node true")
        run("alice", f"{SSH} dev0-hetz true")
        assert browser_count("alice") == 1

    with subtest("a child vault token is pushed to the node"):
        run("alice", f"{SSH} scoria.dev0-hetz 'sleep 3'")
        scoria.wait_until_succeeds("test -s /home/alice/.vault-token", timeout=60)
        info = scoria.succeed(lookup_ok(scoria, "/home/alice/.vault-token"))
        # vault turns the dots of the display name into dashes
        assert "token-tvbeat-auth-scoria-dev0-hetz" in info, info
        assert '"orphan":false' in info and '"identity_policies":["all"]' in info, info
        scoria.succeed("test -s /home/alice/.cache/tvbeat-auth/vault-token.meta")  # marked as ours

    with subtest("parallel ssh from a cold start signs in exactly once"):
        run("alice", "tvbeat-auth logout")
        scoria.wait_until_fails(lookup_ok(scoria, "/home/alice/.vault-token"))  # logout revoked the pushed child token too
        before = browser_count("alice")
        run("alice", "for i in 1 2 3 4 5 6; do (" + SSH + " scoria.dev0-hetz \"echo ok\" > /tmp/par.$i 2> /tmp/par-err.$i || echo FAIL >> /tmp/par.$i) & done; wait")
        outs = run("alice", "cat /tmp/par.*")
        assert outs.split() == ["ok"] * 6, outs + run("alice", "tail -n 20 /tmp/par-err.*")
        assert browser_count("alice") == before + 1
        # every connection to a node comes from the jump host's address, so
        # sshd must never have cause to penalise it (PerSourcePenalties):
        # token pushes are not cut off half way, nor started six at a time
        client.sleep(12)  # let in-flight pushes finish
        # (the test driver's own open-port probe on ::1 does get one; not us)
        scoria.fail("journalctl -u sshd.service --no-pager | grep srclimit_penalise | grep -v -e ' ::1/128 ' -e ' 127.0.0.1/32 '")

    with subtest("an expired vault token in a week-old tmux session signs in again on the spot"):
        run("alice", f"{SSH} scoria.dev0-hetz 'sleep 3'")  # a fresh token is pushed
        scoria.wait_until_succeeds(lookup_ok(scoria, "/home/alice/.vault-token"), timeout=60)
        tmux("alice", "new-session -d -s work -x 160 -y 60")
        started = tmux("alice", "display-message -p -t work '#{session_created}'").strip()

        # the vault CLI goes through tvbeat-auth (token helper) and gets the pushed token
        in_pane("alice", "work", "vault token lookup -format=json > /tmp/th1.json 2>&1; echo $? > /tmp/th1.rc")
        scoria.wait_until_succeeds("test -s /tmp/th1.rc", timeout=60)
        assert scoria.succeed("cat /tmp/th1.rc").strip() == "0", scoria.succeed("cat /tmp/th1.json")
        assert "tvbeat-auth-scoria-dev0-hetz" in scoria.succeed("cat /tmp/th1.json")

        # days later the token is gone (revoked here; to vault that is the same)
        scoria.succeed("curl -fsS -X POST -H \"X-Vault-Token: $(cat /home/alice/.vault-token)\" http://idp:8200/v1/auth/token/revoke-self")

        # with no terminal around nothing waits for a person: vault fails at once
        rc = scoria.succeed("setsid -w su - alice -c 'timeout 60 vault token lookup > /dev/null 2>&1; echo $?' < /dev/null").strip()
        assert rc not in ("0", "124"), rc

        # the next vault command in the same session shows a device code ...
        in_pane("alice", "work", "vault token lookup -format=json > /tmp/th2.json 2> /tmp/th2.err; echo $? > /tmp/th2.rc")
        pane = "tmux capture-pane -p -J -S - -t work"
        scoria.wait_until_succeeds(
            f"su - alice -c {shlex.quote(pane)} | grep -A2 'enter the code' | tail -1 | grep -E '[A-Z]{{4}}-[A-Z]{{4}}'", timeout=120
        )
        screen = tmux("alice", "capture-pane -p -J -S - -t work")
        assert "Your vault token has expired." in screen, screen
        code = scoria.succeed(f"su - alice -c {shlex.quote(pane)} | grep -A2 'enter the code' | tail -1").strip()
        # ... the person approves it on their phone, and the command carries on
        approve_code(code, "alice")
        scoria.wait_until_succeeds("test -s /tmp/th2.rc", timeout=120)
        assert scoria.succeed("cat /tmp/th2.rc").strip() == "0", scoria.succeed("cat /tmp/th2.err; cat /tmp/th2.json")
        assert '"path": "auth/google/login"' in scoria.succeed("cat /tmp/th2.json")
        assert tmux("alice", "display-message -p -t work '#{session_created}'").strip() == started  # same session

        # the new token is in ~/.vault-token for tools that read the file, marked as ours
        scoria.succeed(lookup_ok(scoria, "/home/alice/.vault-token"))
        scoria.succeed("test -s /home/alice/.cache/tvbeat-auth/vault-token.meta")
        # and the next connect does not swap it for a shorter-lived pushed one
        token = scoria.succeed("cat /home/alice/.vault-token")
        run("alice", "rm -f ~/.config/tvbeat-auth/pushed.json")
        run("alice", f"{SSH} scoria.dev0-hetz 'sleep 3'")
        assert scoria.succeed("cat /home/alice/.vault-token") == token
        tmux("alice", "kill-server")

    with subtest("an expired certificate is replaced without a sign-in"):
        before = browser_count("alice")
        client.sleep(${toString (certTTL + 5)})
        out = run("alice", "ssh-add -l || true")
        assert "tvbeat-auth" not in out, out  # the agent dropped it on expiry
        run("alice", f"{SSH} scoria.dev0-hetz true")
        assert browser_count("alice") == before

    with subtest("an expired sign-in asks again"):
        run("alice", "curl -fsS -X POST -H \"X-Vault-Token: $(cat ~/.config/tvbeat-auth/vault-token)\" http://idp:8200/v1/auth/token/revoke-self")
        run("alice", "ssh-add -D")
        before = browser_count("alice")
        run("alice", f"{SSH} scoria.dev0-hetz true")
        assert browser_count("alice") == before + 1

    with subtest("roles stay separate: an 'all' certificate cannot be root, alice cannot get 'devops'"):
        run("alice", f"{SSH} root@scoria.dev0-hetz true", expect_fail=True)
        run("alice", "tvbeat-auth setup --role devops")
        out = run("alice", "tvbeat-auth login > /tmp/alice-devops 2>&1; echo rc=$?; cat /tmp/alice-devops")
        assert out.startswith("rc=1"), out
        assert "not allowed to use the \"sso-devops\" ssh role" in out, out
        run("alice", "tvbeat-auth setup --role all")

    with subtest("device sign-in: bob (devops) becomes root on the node"):
        run("bob", f"tvbeat-auth setup --username bob --role devops --login device --site {SITE}")
        run("bob", f"({SSH} root@scoria.dev0-hetz 'id -un' > /tmp/bob.out 2> /tmp/bob.err; echo $? > /tmp/bob.rc) > /dev/null 2>&1 &", extra="TVBEAT_AUTH_INTERACTIVE=1")
        approve_pending(client, "/tmp/bob.err", "bob")
        client.wait_until_succeeds("test -s /tmp/bob.rc", timeout=120)
        assert client.succeed("cat /tmp/bob.rc").strip() == "0", client.succeed("cat /tmp/bob.err")
        assert client.succeed("cat /tmp/bob.out").strip() == "root"

    with subtest("someone outside all@tvbeat.com is turned away by vault"):
        run("mallory", f"tvbeat-auth setup --username mallory --site {SITE}")
        out = run("mallory", "tvbeat-auth login > /tmp/mallory 2>&1; echo rc=$?; cat /tmp/mallory", extra="TVBEAT_AUTH_LOGIN=browser")
        assert out.startswith("rc=1"), out
        assert "vault rejected the sign-in" in out, out

    with subtest("vault-login on a headless server uses the device flow and the server's site file"):
        scoria.succeed("rm -f /home/alice/.vault-token /tmp/vl.*")
        scoria.succeed("systemd-run --uid=alice --setenv=HOME=/home/alice --setenv=PATH=/run/current-system/sw/bin --unit=vault-login /run/current-system/sw/bin/sh -c 'tvbeat-auth vault-login > /tmp/vl.out 2> /tmp/vl.err; echo $? > /tmp/vl.rc'")
        approve_pending(scoria, "/tmp/vl.err", "alice")
        scoria.wait_until_succeeds("test -s /tmp/vl.rc", timeout=120)
        assert scoria.succeed("cat /tmp/vl.rc").strip() == "0", scoria.succeed("cat /tmp/vl.err")
        scoria.succeed(lookup_ok(scoria, "/home/alice/.vault-token"))

    with subtest("without an ssh-agent the key lives in files"):
        run("alice", "tvbeat-auth logout")
        out = run("alice", f"unset SSH_AUTH_SOCK; {SSH} scoria.dev0-hetz 'echo ok'")
        assert out.strip() == "ok", out
        run("alice", "test \"$(stat -c %a ~/.ssh/tvbeat/id_ed25519)\" = 600")
        run("alice", "test ! -e ~/.ssh/tvbeat/agent-cert.pub")

    with subtest("the vault OIDC flow (today's setup) still works"):
        run("alice", f"tvbeat-auth logout; tvbeat-auth setup --site {LEGACY_SITE}")
        out = run("alice", f"{SSH} scoria.dev0-hetz 'id -un'")
        assert out.strip() == "alice", out

    with subtest("configs written by tvbeat-ssh 1.x keep working, until setup takes over"):
        legacy = f"TVBEAT_AUTH_SITE={LEGACY_SITE}"
        # (install, not cp: the originals are read-only store files, and a
        # read-only ~/.ssh/config is rightly left alone by setup)
        run("dave", "install -D -m 600 -t ~/.ssh /etc/tvbeat-test/1x/tvbeat.conf /etc/tvbeat-test/1x/config")
        # 1.x's `Match exec "tvbeat-ssh sign --role all"` now reaches tvbeat-auth
        out = run("dave", f"{SSH} dev0-hetz+scoria.node 'id -un'", extra=legacy)
        assert out.strip() == "dave", out
        assert browser_count("dave") == 1
        run("dave", "test -s ~/.cache/tvbeat/.ssh/id_ed25519-cert.pub")
        run("dave", "test ! -e ~/.cache/tvbeat/.vault-token")  # the old token copy is never made
        run("dave", f"{SSH} dev0-hetz+scoria.node true", extra=legacy)
        assert browser_count("dave") == 1

        # setup: username from the account, the 1.x config retired, no second sign-in
        out = run("dave", "tvbeat-auth setup", extra=legacy)
        assert "Retired the configuration from tvbeat-ssh 1.x" in out, out
        assert "All set, dave." in out, out
        run("dave", "test -e ~/.ssh/tvbeat.conf.old && test ! -e ~/.ssh/tvbeat.conf")
        run("dave", "! grep -q 'Include tvbeat.conf' ~/.ssh/config")
        out = run("dave", f"{SSH} scoria.dev0-hetz 'id -un'", extra=legacy)
        assert out.strip() == "dave", out
        assert browser_count("dave") == 1

    with subtest("nothing was ever trusted on first use"):
        for u in ["alice", "bob", "carol"]:
            run(u, "test ! -s ~/.ssh/known_hosts")
  '';
}
