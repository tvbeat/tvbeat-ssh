{ system ? builtins.currentSystem
, nixpkgs
}:
let
  pkgs = import nixpkgs {
    inherit system;
  };
in
{
  overlays.default = final: _: {
    tvbeat-ssh = final.buildGoModule {
      pname = "tvbeat-ssh";
      version = "1.0.1";
      src = ./src;
      vendorHash = "sha256-zrjQaDF/h5Lq2vivJ9vDAw1kTOh7cmHH3z1iBhewpzY=";
    };
  };

  packages.default = pkgs.buildGoModule {
    pname = "tvbeat-ssh";
    version = "1.0.1";
    src = ./src;
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
