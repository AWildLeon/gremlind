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
        default = pkgs.buildGoModule {
          pname = "gremlind";
          version = "0.1.0";
          src = self;
          vendorHash = "sha256-Ir2ixFJze34VFVr3CWT9GIi5uH9XDfEKvP64KIeoAbg=";
          # GRE/netlink code is Linux-only.
          ldflags = [ "-s" "-w" ];
          meta = {
            description = "Dynamic control-plane daemon for GRE tunnels";
            mainProgram = "gremlind";
            platforms = pkgs.lib.platforms.linux;
          };
        };
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

      nixosModules.gremlind = { config, lib, pkgs, ... }:
        let
          cfg = config.services.gremlind;
        in
        {
          options.services.gremlind = {
            enable = lib.mkEnableOption "gremlind GRE control-plane daemon";
            package = lib.mkOption {
              type = lib.types.package;
              default = self.packages.${pkgs.system}.default;
              description = "gremlind package to run.";
            };
            role = lib.mkOption {
              type = lib.types.enum [ "server" "connect" ];
              default = "server";
              description = "Run as concentrator (server) or dialer (connect).";
            };
            configFile = lib.mkOption {
              type = lib.types.path;
              description = "Path to the gremlind YAML config.";
            };
            connectTo = lib.mkOption {
              type = lib.types.nullOr lib.types.str;
              default = null;
              description = "Server address:port when role = connect.";
            };
          };

          config = lib.mkIf cfg.enable {
            systemd.services.gremlind = {
              description = "gremlind GRE control-plane daemon";
              wantedBy = [ "multi-user.target" ];
              after = [ "network-online.target" ];
              wants = [ "network-online.target" ];
              serviceConfig = {
                ExecStart =
                  if cfg.role == "server" then
                    "${lib.getExe cfg.package} server -c ${cfg.configFile}"
                  else
                    "${lib.getExe cfg.package} connect ${cfg.connectTo} -c ${cfg.configFile}";
                Restart = "on-failure";
                RestartSec = 3;
                AmbientCapabilities = [ "CAP_NET_ADMIN" ];
                CapabilityBoundingSet = [ "CAP_NET_ADMIN" ];
                DynamicUser = true;
                ProtectSystem = "strict";
                ProtectHome = true;
              };
            };
          };
        };
    };
}
