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
          vendorHash = "sha256-RuUXxEafz+DVsUWjTiJWcvVpPeEZpWZkBXxBlpoBcT8=";
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
            netlinkd = {
              enable = lib.mkEnableOption "separate privileged gremlind netlink broker";
              socket = lib.mkOption {
                type = lib.types.str;
                default = "/run/gremlind-netlink.sock";
                description = "Unix socket for gremlind netlinkd; set netlink_socket to this path in gremlind.yaml.";
              };
              group = lib.mkOption {
                type = lib.types.str;
                default = "gremlind-netlink";
                description = "Group allowed to talk to the netlink broker socket.";
              };
              greLocal = lib.mkOption {
                type = lib.types.nullOr lib.types.str;
                default = null;
                description = "Optional GRE local address allow-list enforced by netlinkd.";
              };
            };
          };

          config = lib.mkIf cfg.enable {
            users.groups = lib.mkIf cfg.netlinkd.enable { ${cfg.netlinkd.group} = {}; };

            systemd.services.gremlind = {
              description = "gremlind GRE control-plane daemon";
              wantedBy = [ "multi-user.target" ];
              after = [ "network-online.target" ] ++ lib.optional cfg.netlinkd.enable "gremlind-netlinkd.service";
              wants = [ "network-online.target" ] ++ lib.optional cfg.netlinkd.enable "gremlind-netlinkd.service";
              serviceConfig = {
                ExecStart =
                  if cfg.role == "server" then
                    "${lib.getExe cfg.package} server -c ${cfg.configFile}"
                  else
                    "${lib.getExe cfg.package} connect ${cfg.connectTo} -c ${cfg.configFile}";
                Restart = "on-failure";
                RestartSec = 3;
                UMask = "0077";
                AmbientCapabilities = lib.optional (!cfg.netlinkd.enable) "CAP_NET_ADMIN";
                CapabilityBoundingSet = lib.optional (!cfg.netlinkd.enable) "CAP_NET_ADMIN";
                NoNewPrivileges = true;
                DynamicUser = true;
                SupplementaryGroups = lib.optional cfg.netlinkd.enable cfg.netlinkd.group;
                PrivateTmp = true;
                LockPersonality = true;
                MemoryDenyWriteExecute = true;
                ProtectSystem = "strict";
                ProtectHome = true;
                ProtectClock = true;
                ProtectControlGroups = true;
                ProtectKernelLogs = true;
                ProtectKernelModules = true;
                ProtectKernelTunables = true;
                RestrictAddressFamilies = [ "AF_INET" "AF_INET6" "AF_UNIX" ] ++ lib.optional (!cfg.netlinkd.enable) "AF_NETLINK";
                RestrictNamespaces = true;
                RestrictRealtime = true;
                SystemCallArchitectures = "native";
                SystemCallFilter = [ "~@mount" "~@swap" "~@reboot" "~@obsolete" "~@cpu-emulation" "~@debug" "~@module" "~keyctl" "~bpf" ];
              };
            };

            systemd.services.gremlind-netlinkd = lib.mkIf cfg.netlinkd.enable {
              description = "gremlind privileged netlink broker";
              wantedBy = [ "multi-user.target" ];
              after = [ "network-online.target" ];
              wants = [ "network-online.target" ];
              serviceConfig = {
                ExecStart = "${lib.getExe cfg.package} netlinkd -s ${cfg.netlinkd.socket} -mode 0660 -group ${cfg.netlinkd.group}"
                  + lib.optionalString (cfg.netlinkd.greLocal != null) " -gre-local ${cfg.netlinkd.greLocal}";
                Restart = "on-failure";
                RestartSec = 3;
                UMask = "0077";
                AmbientCapabilities = [ "CAP_NET_ADMIN" ];
                CapabilityBoundingSet = [ "CAP_NET_ADMIN" ];
                NoNewPrivileges = true;
                DynamicUser = true;
                SupplementaryGroups = [ cfg.netlinkd.group ];
                PrivateTmp = true;
                LockPersonality = true;
                MemoryDenyWriteExecute = true;
                ProtectSystem = "strict";
                ProtectHome = true;
                ProtectClock = true;
                ProtectControlGroups = true;
                ProtectKernelLogs = true;
                ProtectKernelModules = true;
                ProtectKernelTunables = true;
                RestrictAddressFamilies = [ "AF_NETLINK" "AF_UNIX" ];
                RestrictNamespaces = true;
                RestrictRealtime = true;
                SystemCallArchitectures = "native";
                SystemCallFilter = [ "~@mount" "~@swap" "~@reboot" "~@obsolete" "~@cpu-emulation" "~@debug" "~@module" "~keyctl" "~bpf" ];
              };
            };
          };
        };
    };
}
