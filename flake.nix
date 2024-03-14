{
  description = "a small helper script to grant you ssh access to tvbeat systems";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/release-23.11";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        packages.default = pkgs.buildGoModule {
          name = "tvbeat-ssh";
          src = ./.;
          vendorHash = "sha256-+iRplE8gB0aFzHXuYGFdabHCmSeQRn+YZ+Q4N5mhlYQ=";
        };

        devShells.default = with pkgs;
          mkShell {
            name = "tvbeat-ssh";
            packages = [
              go
              gotools
              gopls
              go-outline
              gocode
              gopkgs
              gocode-gomod
              godef
              golint
            ];
          };
      }
    );
}
