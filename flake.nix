{
  description = "tvbeat-auth - sign in to tvbeat systems: ssh with short-lived certificates from vault, vault tokens";

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
        packages.default = pkgs.tvbeat-auth;
        packages.tvbeat-auth = pkgs.tvbeat-auth;

        checks = {
          inherit (pkgs) tvbeat-auth;
        } // pkgs.lib.optionalAttrs pkgs.stdenv.isLinux {
          vm = import ./nix/tests/vm.nix { inherit pkgs self; };
        };

        devShells.default = pkgs.mkShell {
          name = "tvbeat-auth";
          packages = with pkgs; [ go gopls gotools go-tools ];
        };
      }
    ) // {
      overlays.default = import ./nix/overlay.nix { inherit self; };
      nixosModules.default = import ./nix/module.nix { inherit self; };
    };
}
