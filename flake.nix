{
  description = "a small helper script to grant you ssh access to tvbeat systems";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        packages.default = pkgs.writeShellApplication {
          name = "tvbeat-ssh";
          runtimeInputs = with pkgs; [
            gnugrep
            gnused
            jq
            vault
          ];
          text = builtins.readFile ./tvbeat-ssh;
        };

        checks.default = pkgs.runCommand "shellcheck" { nativeBuildInputs = [ pkgs.shellcheck ]; } ''
          shellcheck ${self}/tvbeat-ssh > $out
        '';

        devShells.default = with pkgs;
          mkShell {
            name = "tvbeat-ssh";
            packages = [
              shellcheck

              gnugrep
              gnused
              jq
              vault
            ];
          };
      }
    );
}
