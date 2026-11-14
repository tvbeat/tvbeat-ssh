# NixOS module for servers people ssh into: installs tvbeat-auth and makes
# it the vault CLI's token helper, so an expired vault token (say, in a tmux
# session that has been open all week) turns into a device-code sign-in on
# the spot instead of an error.
{ self }:
{ config, lib, pkgs, ... }:
let
  cfg = config.programs.tvbeat-auth;
  inherit (lib) mkEnableOption mkIf mkOption types;

  # vault wants an absolute path to an existing file, without arguments
  tokenHelper = pkgs.writeShellScript "tvbeat-auth-vault-token-helper" ''
    exec ${lib.getExe cfg.package} token-helper "$@"
  '';
in
{
  options.programs.tvbeat-auth = {
    enable = mkEnableOption "tvbeat-auth: `tvbeat-auth vault-login` and the vault token helper";

    package = mkOption {
      type = types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
      defaultText = lib.literalExpression "tvbeat-auth.packages.\${system}.default";
      description = "The tvbeat-auth package.";
    };

    site = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = ''
        Site description (JSON) installed as /etc/tvbeat-auth/site.json. Leave
        null to use the one built into tvbeat-auth.
      '';
    };

    vaultTokenHelper = mkOption {
      type = types.bool;
      default = true;
      description = ''
        Point the vault CLI's `token_helper` at tvbeat-auth, system wide
        (VAULT_CONFIG_PATH). Tokens still live in ~/.vault-token, where
        tvbeat-auth on people's laptops puts them on connect.
      '';
    };
  };

  config = mkIf cfg.enable {
    environment.systemPackages = [ cfg.package ];

    environment.etc."tvbeat-auth/site.json" = mkIf (cfg.site != null) { source = cfg.site; };

    environment.etc."vault/tvbeat-auth.hcl" = mkIf cfg.vaultTokenHelper {
      text = ''
        token_helper = "${tokenHelper}"
      '';
    };
    environment.variables.VAULT_CONFIG_PATH = mkIf cfg.vaultTokenHelper "/etc/vault/tvbeat-auth.hcl";
  };
}
