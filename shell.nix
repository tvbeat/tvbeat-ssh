let
  sources = import ./lon.nix;
in
{ nixpkgs ? sources.nixpkgs }:
let
  outputs = import ./default.nix { inherit nixpkgs; };
in
  outputs.devShells.default
