{ self }:
final: _: {
  tvbeat-ssh = final.buildGoModule {
    pname = "tvbeat-ssh";
    version = "2.0.0-dev";
    src = final.lib.cleanSourceWith {
      src = self;
      filter = path: type:
        let base = baseNameOf path; in
        !(final.lib.hasSuffix ".nix" base) && base != "flake.lock" && base != "nix";
    };
    vendorHash = "sha256-7AJnVXu6QjHzOQviaawiuRU6Npmvp9Z3pwnVEE4ivco=";
    subPackages = [ "cmd/tvbeat-ssh" ];
    env.CGO_ENABLED = 0;
    ldflags = [ "-s" "-w" "-X main.version=2.0.0-dev" ];
    meta = {
      description = "ssh access to tvbeat systems with short-lived certificates from vault";
      mainProgram = "tvbeat-ssh";
    };
  };
}
