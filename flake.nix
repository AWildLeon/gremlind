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
          settingsFormat = pkgs.formats.yaml { };

          # Everything except auth/client secrets goes through cfg.settings —
          # a plain YAML-serializable attrset, so new gremlind config fields
          # don't need a matching Nix option added here to be reachable.
          # Secrets never enter cfg.settings (it lands in the Nix store);
          # auth.pskFile / auth.clients / client.secretFile instead name a
          # file on disk (e.g. an agenix secret) that's loaded at service
          # start via systemd's LoadCredential and merged into the runtime
          # config gremlind actually reads.
          settingsFile = settingsFormat.generate "gremlind-settings.yaml" cfg.settings;

          loadCredentials =
            lib.optional (cfg.auth.pskFile != null) "psk:${cfg.auth.pskFile}"
            ++ lib.mapAttrsToList (id: file: "client-${id}:${file}") cfg.auth.clients
            ++ lib.optional (cfg.client.secretFile != null) "secret:${cfg.client.secretFile}";

          renderConfig = pkgs.writeShellScript "gremlind-render-config" ''
            set -eu
            umask 077
            out=/run/gremlind/config.yaml
            cat ${settingsFile} > "$out"
            ${lib.optionalString (cfg.auth.pskFile != null || cfg.auth.clients != { }) ''
              echo 'auth:' >> "$out"
            ''}
            ${lib.optionalString (cfg.auth.pskFile != null) ''
              printf '  psk: "%s"\n' "$(cat "$CREDENTIALS_DIRECTORY/psk")" >> "$out"
            ''}
            ${lib.optionalString (cfg.auth.clients != { }) ''
              echo '  clients:' >> "$out"
              ${lib.concatMapStringsSep "\n" (id: ''
                printf '    ${id}: "%s"\n' "$(cat "$CREDENTIALS_DIRECTORY/client-${id}")" >> "$out"
              '') (lib.attrNames cfg.auth.clients)}
            ''}
            ${lib.optionalString (cfg.client.id != null || cfg.client.secretFile != null) ''
              echo 'client:' >> "$out"
            ''}
            ${lib.optionalString (cfg.client.id != null) ''
              printf '  id: "%s"\n' ${lib.escapeShellArg cfg.client.id} >> "$out"
            ''}
            ${lib.optionalString (cfg.client.secretFile != null) ''
              printf '  secret: "%s"\n' "$(cat "$CREDENTIALS_DIRECTORY/secret")" >> "$out"
            ''}
          '';
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
            connectTo = lib.mkOption {
              type = lib.types.nullOr lib.types.str;
              default = null;
              description = "Server address:port when role = connect.";
            };
            settings = lib.mkOption {
              type = settingsFormat.type;
              default = { };
              description = ''
                gremlind config, minus auth/client secrets (see auth.* and
                client.* below). Keys match the YAML config fields verbatim —
                e.g. listen, gre_local, inner_pool, server_inner, mtu,
                gre_key, gre_seq, admin_socket, keepalive_interval,
                lease_ttl, hooks.up/hooks.down. See gremlind's README /
                configs/gremlind.example.yaml for the full field list.
              '';
              example = {
                listen = "[::]:4747";
                gre_local = "2001:db8::10";
                inner_pool = "fd00:9::/112";
                server_inner = "fd00:9::1";
              };
            };
            auth = {
              pskFile = lib.mkOption {
                type = lib.types.nullOr lib.types.path;
                default = null;
                description = ''
                  File holding the global auth.psk (server role). Loaded via
                  systemd LoadCredential at service start — never copied into
                  the Nix store. Mutually compatible with auth.clients (the
                  daemon prefers a matching per-client secret when both are
                  set).
                '';
              };
              clients = lib.mkOption {
                type = lib.types.attrsOf lib.types.path;
                default = { };
                description = ''
                  Map of client id -> file holding that client's secret
                  (server role, auth.clients). Each is loaded via systemd
                  LoadCredential. Prefer this over auth.pskFile once more
                  than one site dials in, so one site's key can't
                  authenticate as another.
                '';
                example = {
                  site-a = "/run/agenix/gremlind_site_a";
                };
              };
            };
            client = {
              id = lib.mkOption {
                type = lib.types.nullOr lib.types.str;
                default = null;
                description = "This client's id (connect role, matched against the server's auth.clients).";
              };
              secretFile = lib.mkOption {
                type = lib.types.nullOr lib.types.path;
                default = null;
                description = "File holding this client's secret (connect role). Loaded via systemd LoadCredential.";
              };
            };
            netlinkd = {
              enable = lib.mkEnableOption "separate privileged gremlind netlink broker";
              socket = lib.mkOption {
                type = lib.types.str;
                default = "/run/gremlind-netlink.sock";
                description = "Unix socket for gremlind netlinkd; set netlink_socket to this path in cfg.settings.";
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
            assertions = [
              {
                assertion = cfg.role != "connect" || cfg.connectTo != null;
                message = "services.gremlind.connectTo is required when role = connect.";
              }
            ];

            users.groups = lib.mkIf cfg.netlinkd.enable { ${cfg.netlinkd.group} = {}; };

            systemd.services.gremlind = {
              description = "gremlind GRE control-plane daemon";
              wantedBy = [ "multi-user.target" ];
              after = [ "network-online.target" ] ++ lib.optional cfg.netlinkd.enable "gremlind-netlinkd.service";
              wants = [ "network-online.target" ] ++ lib.optional cfg.netlinkd.enable "gremlind-netlinkd.service";
              serviceConfig = {
                RuntimeDirectory = "gremlind";
                LoadCredential = loadCredentials;
                ExecStartPre = "${renderConfig}";
                ExecStart =
                  if cfg.role == "server" then
                    "${lib.getExe cfg.package} server -c /run/gremlind/config.yaml"
                  else
                    "${lib.getExe cfg.package} connect ${cfg.connectTo} -c /run/gremlind/config.yaml";
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
