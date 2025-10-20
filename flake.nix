{
  description = "a small helper script to grant you ssh access to tvbeat systems";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/release-24.05";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        outputs = import ./default.nix { inherit system nixpkgs; };
      in
      {
        inherit (outputs) packages devShells;
      }
    ) // {
      inherit (import ./default.nix { nixpkgs = null; }) overlays;
    };
}
