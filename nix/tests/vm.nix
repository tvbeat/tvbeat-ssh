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
      browser.id = "tvbeat-ssh-desktop";
      device.id = "tvbeat-ssh-device";
    };
    ssh_roles = { all = "sso-all"; devops = "sso-devops"; };
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

  people = {
    alice = [ "alice@tvbeat.com" ];
    bob = [ "bob@tvbeat.com" ];
    mallory = [ "mallory@tvbeat.com" ];
  };

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
  name = "tvbeat-ssh";

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
      imports = [ (sshServer 22) ];
      environment.systemPackages = [ pkgs.tvbeat-ssh pkgs.curl ];
      environment.etc."tvbeat-ssh/site.json".source = site;
    };

    client = { nodes, ... }: {
      environment.systemPackages = [ pkgs.tvbeat-ssh pkgs.curl pkgs.jq testScripts ];
      environment.etc."tvbeat-ssh/site.json".source = site;
      environment.etc."tvbeat-ssh/site-legacy.json".source = siteLegacy;
      networking.extraHosts = "${nodes.jump.networking.primaryIPAddress} jump.dev0-hetz.tvbeat.com";
      users.users = lib.mapAttrs (_: _: { isNormalUser = true; }) people;
    };
  };

  testScript = ''
    import shlex

    SSH = "ssh -o BatchMode=yes"

    def env(user, extra=""):
        return (
            f"export SSH_AUTH_SOCK=/tmp/{user}-agent.sock"
            f" TVBEAT_SSH_BROWSER=fake-browser FAKE_LOGIN={user}@tvbeat.com FAKE_PASSWORD=password"
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

    def approve_pending(machine, errfile, user):
        """the person on their phone: read the code, approve it in dex"""
        machine.wait_until_succeeds(f"grep -A2 'enter the code' {errfile} | tail -1 | grep -E '[A-Z]{{4}}-[A-Z]{{4}}'", timeout=120)
        code = machine.succeed(f"grep -A2 'enter the code' {errfile} | tail -1").strip()
        client.succeed(f"FAKE_LOGIN={user}@tvbeat.com FAKE_PASSWORD=password approve-device ${issuer} {code}")

    start_all()

    with subtest("vault and dex come up and vault is configured like production"):
        idp.wait_for_unit("vault-dev.service")
        idp.wait_for_unit("dex.service")
        idp.wait_until_succeeds("curl -fs http://127.0.0.1:8200/v1/sys/health")
        idp.wait_until_succeeds("curl -fs ${issuer}/.well-known/openid-configuration")
        idp.succeed(
            "ISSUER=${issuer} BROWSER_CLIENT_ID=vault BROWSER_CLIENT_SECRET=vault-secret"
            " DESKTOP_CLIENT_ID=tvbeat-ssh-desktop DEVICE_CLIENT_ID=tvbeat-ssh-device"
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
    for u in ["alice", "bob", "mallory"]:
        run(u, f"ssh-agent -a /tmp/{u}-agent.sock > /dev/null")

    with subtest("config writes ssh config and a CA-only known_hosts"):
        out = run("alice", "tvbeat-ssh config --username alice --login browser --site /etc/tvbeat-ssh/site.json")
        assert "no fingerprint prompts" in out, out
        run("alice", "grep -qx 'Include ~/.ssh/tvbeat/config' ~/.ssh/config")
        run("alice", "grep -q '^@cert-authority .*dev0-hetz' ~/.ssh/tvbeat/known_hosts")
        # idempotent
        run("alice", "tvbeat-ssh config --username alice --site /etc/tvbeat-ssh/site.json")
        assert run("alice", "grep -c tvbeat/config ~/.ssh/config").strip() == "1"
        run("alice", "tvbeat-ssh check-host scoria.dev0-hetz")
        run("alice", "tvbeat-ssh check-host dev0-hetz+scoria.node")
        run("alice", "tvbeat-ssh check-host github.com", expect_fail=True)

    with subtest("first ssh signs in through the browser, no host key prompt"):
        out = run("alice", f"{SSH} scoria.dev0-hetz 'id -un; hostname'")
        assert out.split() == ["alice", "scoria"], out
        assert browser_count("alice") == 1
        out = run("alice", "ssh-add -l")
        assert "tvbeat-ssh role=all (ED25519-CERT)" in out, out
        run("alice", "test ! -e ~/.ssh/tvbeat/id_ed25519")  # key only in the agent

    with subtest("later connections need no sign-in; all spellings and the jump host work"):
        run("alice", f"{SSH} scoria.dev0-hetz true")
        run("alice", f"{SSH} dev0-hetz+scoria.node true")
        run("alice", f"{SSH} dev0-hetz true")
        assert browser_count("alice") == 1

    with subtest("a child vault token is pushed to the node"):
        run("alice", f"{SSH} scoria.dev0-hetz 'sleep 3'")
        scoria.wait_until_succeeds("test -s /home/alice/.vault-token", timeout=60)
        info = scoria.succeed(
            "curl -fsS -H \"X-Vault-Token: $(cat /home/alice/.vault-token)\" http://idp:8200/v1/auth/token/lookup-self"
        )
        # vault turns the dots of the display name into dashes
        assert "token-tvbeat-ssh-scoria-dev0-hetz" in info, info
        assert '"orphan":false' in info and '"identity_policies":["all"]' in info, info

    with subtest("parallel ssh from a cold start signs in exactly once"):
        run("alice", "tvbeat-ssh logout")
        scoria.wait_until_fails(
            "curl -fsS -H \"X-Vault-Token: $(cat /home/alice/.vault-token)\" http://idp:8200/v1/auth/token/lookup-self"
        )  # logout revoked the pushed child token too
        before = browser_count("alice")
        run("alice", "for i in 1 2 3 4 5 6; do (" + SSH + " scoria.dev0-hetz \"echo ok\" > /tmp/par.$i 2> /tmp/par-err.$i || echo FAIL >> /tmp/par.$i) & done; wait")
        outs = run("alice", "cat /tmp/par.*")
        assert outs.split() == ["ok"] * 6, outs
        assert browser_count("alice") == before + 1

    with subtest("an expired certificate is replaced without a sign-in"):
        before = browser_count("alice")
        client.sleep(${toString (certTTL + 5)})
        out = run("alice", "ssh-add -l || true")
        assert "tvbeat-ssh" not in out, out  # the agent dropped it on expiry
        run("alice", f"{SSH} scoria.dev0-hetz true")
        assert browser_count("alice") == before

    with subtest("an expired sign-in asks again"):
        run("alice", "curl -fsS -X POST -H \"X-Vault-Token: $(cat ~/.config/tvbeat-ssh/vault-token)\" http://idp:8200/v1/auth/token/revoke-self")
        run("alice", "ssh-add -D")
        before = browser_count("alice")
        run("alice", f"{SSH} scoria.dev0-hetz true")
        assert browser_count("alice") == before + 1

    with subtest("roles stay separate: an 'all' certificate cannot be root, alice cannot get 'devops'"):
        run("alice", f"{SSH} root@scoria.dev0-hetz true", expect_fail=True)
        run("alice", "tvbeat-ssh config --role devops")
        out = run("alice", "tvbeat-ssh login > /tmp/alice-devops 2>&1; echo rc=$?; cat /tmp/alice-devops")
        assert out.startswith("rc=1"), out
        assert "not allowed to use the \"sso-devops\" ssh role" in out, out
        run("alice", "tvbeat-ssh config --role all")

    with subtest("device sign-in: bob (devops) becomes root on the node"):
        run("bob", "tvbeat-ssh config --username bob --role devops --login device --site /etc/tvbeat-ssh/site.json")
        run("bob", f"({SSH} root@scoria.dev0-hetz 'id -un' > /tmp/bob.out 2> /tmp/bob.err; echo $? > /tmp/bob.rc) > /dev/null 2>&1 &", extra="TVBEAT_SSH_INTERACTIVE=1")
        approve_pending(client, "/tmp/bob.err", "bob")
        client.wait_until_succeeds("test -s /tmp/bob.rc", timeout=120)
        assert client.succeed("cat /tmp/bob.rc").strip() == "0", client.succeed("cat /tmp/bob.err")
        assert client.succeed("cat /tmp/bob.out").strip() == "root"

    with subtest("someone outside all@tvbeat.com is turned away by vault"):
        run("mallory", "tvbeat-ssh config --username mallory --site /etc/tvbeat-ssh/site.json")
        out = run("mallory", "tvbeat-ssh login > /tmp/mallory 2>&1; echo rc=$?; cat /tmp/mallory", extra="TVBEAT_SSH_LOGIN=browser")
        assert out.startswith("rc=1"), out
        assert "vault rejected the sign-in" in out, out

    with subtest("vault-login on a headless server uses the device flow"):
        scoria.succeed("su - alice -c 'rm -f ~/.vault-token; (tvbeat-ssh vault-login --site /etc/tvbeat-ssh/site.json > /tmp/vl.out 2> /tmp/vl.err; echo $? > /tmp/vl.rc) > /dev/null 2>&1 &'")
        approve_pending(scoria, "/tmp/vl.err", "alice")
        scoria.wait_until_succeeds("test -s /tmp/vl.rc", timeout=120)
        assert scoria.succeed("cat /tmp/vl.rc").strip() == "0", scoria.succeed("cat /tmp/vl.err")
        scoria.succeed("curl -fsS -H \"X-Vault-Token: $(cat /home/alice/.vault-token)\" http://idp:8200/v1/auth/token/lookup-self")

    with subtest("without an ssh-agent the key lives in files"):
        run("alice", "tvbeat-ssh logout")
        out = run("alice", f"unset SSH_AUTH_SOCK; {SSH} scoria.dev0-hetz 'echo ok'")
        assert out.strip() == "ok", out
        run("alice", "test \"$(stat -c %a ~/.ssh/tvbeat/id_ed25519)\" = 600")
        run("alice", "test ! -e ~/.ssh/tvbeat/agent-cert.pub")

    with subtest("the vault OIDC flow (today's setup) still works"):
        run("alice", "tvbeat-ssh logout; tvbeat-ssh config --site /etc/tvbeat-ssh/site-legacy.json")
        out = run("alice", f"{SSH} scoria.dev0-hetz 'id -un'")
        assert out.strip() == "alice", out

    with subtest("nothing was ever trusted on first use"):
        run("alice", "test ! -s ~/.ssh/known_hosts")
        run("bob", "test ! -s ~/.ssh/known_hosts")
  '';
}
