{ self }:
final: _: {
  tvbeat-auth = final.buildGoModule rec {
    pname = "tvbeat-auth";
    version = "2.0.0-dev";
    src = final.lib.cleanSourceWith {
      src = self;
      filter = path: type:
        let base = baseNameOf path; in
        !(final.lib.hasSuffix ".nix" base) && base != "flake.lock" && base != "nix";
    };
    vendorHash = "sha256-7AJnVXu6QjHzOQviaawiuRU6Npmvp9Z3pwnVEE4ivco=";
    subPackages = [ "cmd/tvbeat-auth" ];
    env.CGO_ENABLED = 0;
    ldflags = [ "-s" "-w" "-X main.version=${version}" ];
    # ssh configs written by tvbeat-ssh 1.x run `tvbeat-ssh sign`; keep them
    # working until their owner runs `tvbeat-auth setup`
    postInstall = ''
      ln -s tvbeat-auth $out/bin/tvbeat-ssh
    '';
    meta = {
      description = "sign in to tvbeat systems: ssh with short-lived certificates, vault tokens";
      homepage = "https://github.com/tvbeat/tvbeat-auth";
      mainProgram = "tvbeat-auth";
    };
  };

  # tvbeat-ssh 1.x users' flake references keep working
  tvbeat-ssh = final.tvbeat-auth;
}
