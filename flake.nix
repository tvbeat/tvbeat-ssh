{
  description = "tvbeat-ssh - ssh access to tvbeat systems with short-lived certificates from vault";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ self.overlays.default ];
        };
      in
      {
        packages.default = pkgs.tvbeat-ssh;

        checks = {
          inherit (pkgs) tvbeat-ssh;
        } // pkgs.lib.optionalAttrs pkgs.stdenv.isLinux {
          vm = import ./nix/tests/vm.nix { inherit pkgs self; };
        };

        devShells.default = pkgs.mkShell {
          name = "tvbeat-ssh";
          packages = with pkgs; [ go gopls gotools go-tools ];
        };
      }
    ) // {
      overlays.default = import ./nix/overlay.nix { inherit self; };
    };
}
