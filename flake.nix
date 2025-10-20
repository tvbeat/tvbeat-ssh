{
  description = "a small helper script to grant you ssh access to tvbeat systems";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/release-24.05";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;

          overlays = [
            self.overlays.default
          ];
        };
      in
      {
        packages.default = pkgs.tvbeat-ssh;

        devShells.default = with pkgs;
          mkShell {
            name = "tvbeat-ssh";
            packages = [
              go
              gotools
              gopls
              go-outline
              gopls
              gopkgs
              gocode-gomod
              godef
              golint
            ];
          };
      }
    ) // {
      overlays.default = import ./overlays.nix;
    };
}
