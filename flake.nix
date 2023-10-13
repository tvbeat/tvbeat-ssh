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
    ) // {
      nixosModules.lxd =
        { config, pkgs, lib, ... }:
        let
          tvbeat-ssh = self.packages.${config.nixpkgs.system}.default;
          script = pkgs.writeShellApplication {
            name = "script";
            runtimeInputs = [ pkgs.yq ];
            text = ''
              for f in salt/pillar/clusters/*/infra.sls; do
                if [[ ! -f $f ]]; then
                  continue
                fi

                ipv4=$(yq -r ".nodes.\"$1\".public.address" "$f")

                if [[ $ipv4 != "null" ]]; then
                  echo -n "$ipv4"
                  exit 0
                fi
              done

              exit 1
            '';
          };
        in
        {
          programs.ssh.extraConfig = ''
            # convenience wrapper for logging into our lxd clusters
            Match exec "${script}/bin/script %h" exec "${tvbeat-ssh}/bin/tvbeat-ssh sign devops"
              User root
              IdentityFile ~/.cache/tvbeat/.ssh/id_ed25519
              UserKnownHostsFile salt/cache/known_hosts
              StrictHostKeyChecking no
              # https://superuser.com/questions/1633430/ssh-config-with-dynamic-ip
              ProxyCommand bash -c "${pkgs.netcat}/bin/nc $(${script}/bin/script %h) %p"
          '';
        };
    };
}
