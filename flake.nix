{
  description = "a small helper script to grant you ssh access to tvbeat systems";

  inputs = {
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system: { inherit (import ./default.nix { inherit system; }) packages devShells; }) // {
      inherit (import ./default.nix { }) overlays;
    };
}
