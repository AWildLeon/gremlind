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
          vendorHash = "sha256-Dhwe0At6djMzBIBmsR71XBNZYrGPQjmRWFW08SrViMo=";
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
          # Per-client pinned interface names are merged into the server config at
          # runtime (not build time) so a secret-bearing configFile never has to be
          # copied into the world-readable Nix store.
          useIfaceMerge = cfg.role == "server" && cfg.interfaces != { };
          ifaceFragment = (pkgs.formats.yaml { }).generate "gremlind-interfaces.yaml" {
            interfaces = cfg.interfaces;
          };
          mergeConfigScript = pkgs.writeShellScript "gremlind-merge-config" ''
            set -euo pipefail
            umask 0077
            ${pkgs.yq-go}/bin/yq eval-all 'select(fileIndex == 0) * select(fileIndex == 1)' \
              ${cfg.configFile} ${ifaceFragment} > "$RUNTIME_DIRECTORY/config.yaml"
          '';
          effectiveConfig = if useIfaceMerge then "/run/gremlind/config.yaml" else "${cfg.configFile}";
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
            interfaces = lib.mkOption {
              type = lib.types.attrsOf lib.types.str;
              default = { };
              example = { site-a = "gremlin-a"; site-b = "gremlin-b"; };
              description = ''
                Fixed data-plane interface names for specific clients, keyed by
                client ID (server role only). Clients without an entry keep the
                default per-session "grem"+key naming. Names must be <= 15 chars,
                use only [A-Za-z0-9_-] with an alphanumeric first char, be unique,
                and not collide with the auto-generated "grem"+key names.

                These are merged into the server config at service start, and, when
                netlinkd.enable is set, passed to the broker via -iface so it will
                provision them.
              '';
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
                ExecStartPre = lib.optional useIfaceMerge "${mergeConfigScript}";
                RuntimeDirectory = lib.mkIf useIfaceMerge "gremlind";
                RuntimeDirectoryMode = lib.mkIf useIfaceMerge "0700";
                ExecStart =
                  if cfg.role == "server" then
                    "${lib.getExe cfg.package} server -c ${effectiveConfig}"
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
                  + lib.optionalString (cfg.netlinkd.greLocal != null) " -gre-local ${cfg.netlinkd.greLocal}"
                  + lib.concatMapStrings (n: " -iface ${n}") (lib.attrValues cfg.interfaces);
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
