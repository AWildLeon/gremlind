{
  description = "gremlind — a pppd/xl2tpd-style control-plane daemon for GRE tunnels";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = f:
        nixpkgs.lib.genAttrs systems (system: f {
          inherit system;
          pkgs = import nixpkgs { inherit system; };
        });
    in
    {
      packages = forAllSystems ({ pkgs, ... }: {
        default = pkgs.callPackage ./package.nix { };
      });

      apps = forAllSystems ({ system, ... }: {
        default = {
          type = "app";
          program = "${self.packages.${system}.default}/bin/gremlind";
        };
      });

      devShells = forAllSystems ({ pkgs, ... }: {
        default = pkgs.mkShell {
          packages = with pkgs; [
            go
            gopls
            gotools
            go-tools        # staticcheck
            golangci-lint
            iproute2        # `ip`, netns for end-to-end tests
          ];
        };
      });

      nixosModules.gremlind = import ./nixos-module.nix { inherit self; };
    };
}
