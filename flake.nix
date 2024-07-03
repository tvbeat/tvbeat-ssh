{
  description = "a small helper script to grant you ssh access to tvbeat systems";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/release-24.05";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        packages.default = pkgs.buildGoModule {
          pname = "tvbeat-ssh";
          version = "1.0.1";
          src = ./.;
          vendorHash = "sha256-zrjQaDF/h5Lq2vivJ9vDAw1kTOh7cmHH3z1iBhewpzY=";
        };

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
    );
}
