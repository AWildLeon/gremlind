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
          settingsFormat = pkgs.formats.yaml { };

          sourceRuleModule = { ... }: {
            options = {
              ifaces = lib.mkOption {
                type = lib.types.listOf lib.types.str;
                default = [ ];
                description = "Only use source addresses configured on these interfaces; empty means all up interfaces.";
              };
              family = lib.mkOption {
                type = lib.types.enum [ "any" "ipv4" "ipv6" ];
                default = "any";
                description = "Restrict selected source address family.";
              };
              match_server_subnets = lib.mkOption {
                type = lib.types.listOf lib.types.str;
                default = [ ];
                description = "Only apply this rule when the server resolves inside one of these prefixes.";
              };
              include_subnets = lib.mkOption {
                type = lib.types.listOf lib.types.str;
                default = [ ];
                description = "Only allow local source addresses inside these prefixes.";
              };
              exclude_subnets = lib.mkOption {
                type = lib.types.listOf lib.types.str;
                default = [ ];
                description = "Deny local source addresses inside these prefixes.";
              };
            };
          };

          instanceModule = { name, config, ... }: {
            options = {
              enable = lib.mkEnableOption "this gremlind instance" // { default = true; };
              package = lib.mkOption {
                type = lib.types.package;
                default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
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
                iface = lib.mkOption {
                  type = lib.types.nullOr lib.types.str;
                  default = null;
                  description = ''
                    GRE tunnel interface name (connect role). Defaults to
                    "grem0" if unset — set this explicitly whenever a host
                    runs more than one connect instance at once, since two
                    instances defaulting to the same name would collide.
                  '';
                };
                sourceRules = lib.mkOption {
                  type = lib.types.listOf (lib.types.submodule sourceRuleModule);
                  default = [ ];
                  description = ''
                    Ordered source-address selection rules for connect role.
                    Rendered as client.source_rules so they can be combined with
                    secret-backed client.id/secret/iface without duplicate YAML
                    client blocks.
                  '';
                };
                sourceFallback = lib.mkOption {
                  type = lib.types.enum [ "fail" "kernel" ];
                  default = "fail";
                  description = "What to do if sourceRules are configured but no local address matches.";
                };
              };
              useNetlinkd = lib.mkOption {
                type = lib.types.bool;
                default = false;
                description = ''
                  Ask the shared services.gremlind-netlinkd broker to
                  provision GRE interfaces instead of holding CAP_NET_ADMIN
                  directly. Set services.gremlind-netlinkd.enable = true and
                  point this instance's settings.netlink_socket at
                  config.services.gremlind-netlinkd.socket too — netlinkd is
                  a dumb rtnetlink proxy, so one broker is enough for every
                  instance on a host, not one per instance.
                '';
              };
            };
          };
        in
        {
          options.services.gremlind = lib.mkOption {
            type = lib.types.attrsOf (lib.types.submodule instanceModule);
            default = { };
            description = ''
              gremlind instances. Each key is a systemd service
              (gremlind-<name>), so a host can run one server instance and
              several simultaneous connect (dialer) instances to different
              sites side by side — e.g. services.gremlind.eth01.connectTo /
              services.gremlind.ita01.connectTo for the same client roaming
              across (or multi-homed to) two borders at once.
            '';
            example = {
              eth01 = {
                role = "connect";
                connectTo = "[2001:db8::10]:4747";
                client.id = "home-core";
                client.secretFile = "/run/agenix/gremlind_home";
              };
            };
          };

          options.services.gremlind-netlinkd = {
            enable = lib.mkEnableOption ''
              a single shared privileged gremlind netlink broker for every
              services.gremlind instance on this host (split-privilege mode:
              instances that opt in via useNetlinkd ask this broker to
              provision GRE interfaces instead of holding CAP_NET_ADMIN
              themselves)'';
            package = lib.mkOption {
              type = lib.types.package;
              default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
              description = "gremlind package to run.";
            };
            socket = lib.mkOption {
              type = lib.types.str;
              default = "/run/gremlind-netlink.sock";
              description = "Unix socket for gremlind netlinkd; set each instance's settings.netlink_socket to this path.";
            };
            group = lib.mkOption {
              type = lib.types.str;
              default = "gremlind-netlink";
              description = "Group allowed to talk to the netlink broker socket; instances with useNetlinkd = true join it automatically.";
            };
            greLocal = lib.mkOption {
              type = lib.types.nullOr lib.types.str;
              default = null;
              description = "Optional GRE local address allow-list enforced by netlinkd.";
            };
          };

          config =
            let
              # Per-instance derived values, keyed by name — kept out of the
              # config.* tree itself (see the note below on why the
              # config.{assertions,users.groups,systemd.services} generators
              # are three separate mapAttrsToList/mkMerge passes instead of
              # one merged per-instance attrset).
              instanceData = lib.mapAttrs (
                name: cfg:
                let
                  runtimeDir = "gremlind-${name}";
                  configPath = "/run/${runtimeDir}/config.yaml";
                  settingsFile = settingsFormat.generate "gremlind-${name}-settings.yaml" cfg.settings;
                  loadCredentials =
                    lib.optional (cfg.auth.pskFile != null) "psk:${cfg.auth.pskFile}"
                    ++ lib.mapAttrsToList (id: file: "client-${id}:${file}") cfg.auth.clients
                    ++ lib.optional (cfg.client.secretFile != null) "secret:${cfg.client.secretFile}";
                  renderConfig = pkgs.writeShellScript "gremlind-${name}-render-config" ''
                    set -eu
                    umask 077
                    out=${configPath}
                    ${
                      # pkgs.formats.yaml renders {} for empty settings, and
                      # yaml.v3 silently drops everything appended after a
                      # "{}" document root (no error — cfg.Client.ID etc.
                      # just end up empty). Skip the cat entirely when there
                      # are no settings instead of writing that "{}" line.
                      if cfg.settings == { } then ": > \"$out\"" else "cat ${settingsFile} > \"$out\""
                    }
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
                    ${lib.optionalString (cfg.client.id != null || cfg.client.secretFile != null || cfg.client.iface != null || cfg.client.sourceRules != [ ] || cfg.client.sourceFallback != "fail") ''
                      echo 'client:' >> "$out"
                    ''}
                    ${lib.optionalString (cfg.client.id != null) ''
                      printf '  id: "%s"\n' ${lib.escapeShellArg cfg.client.id} >> "$out"
                    ''}
                    ${lib.optionalString (cfg.client.secretFile != null) ''
                      printf '  secret: "%s"\n' "$(cat "$CREDENTIALS_DIRECTORY/secret")" >> "$out"
                    ''}
                    ${lib.optionalString (cfg.client.iface != null) ''
                      printf '  iface: "%s"\n' ${lib.escapeShellArg cfg.client.iface} >> "$out"
                    ''}
                    ${lib.optionalString (cfg.client.sourceFallback != "fail") ''
                      printf '  source_fallback: "%s"\n' ${lib.escapeShellArg cfg.client.sourceFallback} >> "$out"
                    ''}
                    ${lib.optionalString (cfg.client.sourceRules != [ ]) ''
                      echo '  source_rules:' >> "$out"
                      ${lib.concatMapStringsSep "\n" (rule: ''
                        echo '    - family: "${rule.family}"' >> "$out"
                        ${lib.optionalString (rule.ifaces != [ ]) ''
                          echo '      ifaces:' >> "$out"
                          ${lib.concatMapStringsSep "\n" (v: ''printf '        - "%s"\n' ${lib.escapeShellArg v} >> "$out"'') rule.ifaces}
                        ''}
                        ${lib.optionalString (rule.match_server_subnets != [ ]) ''
                          echo '      match_server_subnets:' >> "$out"
                          ${lib.concatMapStringsSep "\n" (v: ''printf '        - "%s"\n' ${lib.escapeShellArg v} >> "$out"'') rule.match_server_subnets}
                        ''}
                        ${lib.optionalString (rule.include_subnets != [ ]) ''
                          echo '      include_subnets:' >> "$out"
                          ${lib.concatMapStringsSep "\n" (v: ''printf '        - "%s"\n' ${lib.escapeShellArg v} >> "$out"'') rule.include_subnets}
                        ''}
                        ${lib.optionalString (rule.exclude_subnets != [ ]) ''
                          echo '      exclude_subnets:' >> "$out"
                          ${lib.concatMapStringsSep "\n" (v: ''printf '        - "%s"\n' ${lib.escapeShellArg v} >> "$out"'') rule.exclude_subnets}
                        ''}
                      '') cfg.client.sourceRules}
                    ''}
                  '';
                in
                { inherit runtimeDir configPath loadCredentials renderConfig; }
              ) config.services.gremlind;
            in
            {
              # A module's own `config` value can't be built as one merged
              # per-instance attrset (`mkMerge (mapAttrsToList mkInstance
              # cfg)` spanning assertions/users.groups/systemd.services
              # together) — evalModules' freeform/unmatched-definitions check
              # ends up forcing that merge while it's still being computed,
              # which is an infinite recursion. Building each config.* leaf
              # with its own mapAttrsToList/mkMerge pass instead sidesteps it.
              assertions = lib.concatLists (
                lib.mapAttrsToList (
                  name: cfg:
                  lib.optional cfg.enable {
                    assertion = cfg.role != "connect" || cfg.connectTo != null;
                    message = "services.gremlind.${name}.connectTo is required when role = connect.";
                  }
                ) config.services.gremlind
              );

              users.groups = lib.mkIf config.services.gremlind-netlinkd.enable {
                ${config.services.gremlind-netlinkd.group} = { };
              };

              systemd.services = lib.mkMerge (
                [
                  (lib.mkIf config.services.gremlind-netlinkd.enable {
                    gremlind-netlinkd =
                      let
                        ncfg = config.services.gremlind-netlinkd;
                      in
                      {
                        description = "gremlind privileged netlink broker";
                        wantedBy = [ "multi-user.target" ];
                        after = [ "network-online.target" ];
                        wants = [ "network-online.target" ];
                        # Keep retrying forever instead of giving up (systemd's
                        # default start-limit) after a handful of failures.
                        startLimitIntervalSec = 0;
                        serviceConfig = {
                          ExecStart = "${lib.getExe ncfg.package} netlinkd -s ${ncfg.socket} -mode 0660 -group ${ncfg.group}"
                            + lib.optionalString (ncfg.greLocal != null) " -gre-local ${ncfg.greLocal}";
                          Restart = "always";
                          RestartSec = 3;
                          UMask = "0077";
                          AmbientCapabilities = [ "CAP_NET_ADMIN" ];
                          CapabilityBoundingSet = [ "CAP_NET_ADMIN" ];
                          NoNewPrivileges = true;
                          DynamicUser = true;
                          SupplementaryGroups = [ ncfg.group ];
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
                  })
                ]
                ++ lib.mapAttrsToList (
                  name: cfg:
                  lib.mkIf cfg.enable (
                    let
                      inherit (instanceData.${name}) runtimeDir configPath loadCredentials renderConfig;
                    in
                    {
                      "gremlind-${name}" = {
                        description = "gremlind GRE control-plane daemon (${name})";
                        wantedBy = [ "multi-user.target" ];
                        after = [ "network-online.target" ] ++ lib.optional cfg.useNetlinkd "gremlind-netlinkd.service";
                        wants = [ "network-online.target" ] ++ lib.optional cfg.useNetlinkd "gremlind-netlinkd.service";
                        # A connect instance that can't reach its server exits
                        # rather than retrying internally, so keep systemd
                        # retrying forever instead of giving up (the default
                        # start-limit) after a handful of failed connects.
                        startLimitIntervalSec = 0;
                        serviceConfig = {
                          RuntimeDirectory = runtimeDir;
                          LoadCredential = loadCredentials;
                          ExecStartPre = "${renderConfig}";
                          ExecStart =
                            if cfg.role == "server" then
                              "${lib.getExe cfg.package} server -c ${configPath}"
                            else
                              "${lib.getExe cfg.package} connect ${cfg.connectTo} -c ${configPath}";
                          Restart = "always";
                          RestartSec = 3;
                          UMask = "0077";
                          AmbientCapabilities = lib.optional (!cfg.useNetlinkd) "CAP_NET_ADMIN";
                          CapabilityBoundingSet = lib.optional (!cfg.useNetlinkd) "CAP_NET_ADMIN";
                          NoNewPrivileges = true;
                          DynamicUser = true;
                          SupplementaryGroups = lib.optional cfg.useNetlinkd config.services.gremlind-netlinkd.group;
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
                          RestrictAddressFamilies = [ "AF_INET" "AF_INET6" "AF_UNIX" ] ++ lib.optional (!cfg.useNetlinkd) "AF_NETLINK";
                          RestrictNamespaces = true;
                          RestrictRealtime = true;
                          SystemCallArchitectures = "native";
                          SystemCallFilter = [ "~@mount" "~@swap" "~@reboot" "~@obsolete" "~@cpu-emulation" "~@debug" "~@module" "~keyctl" "~bpf" ];
                        };
                      };
                    }
                  )
                ) config.services.gremlind
              );
            };
        };
    };
}
