{ lib, buildGoModule }:

buildGoModule {
  pname = "gremlind";
  version = "0.1.0";
  src = ./.;
  vendorHash = "sha256-CJ33GAE7d87w7Ld1hTcjuz34gpqdagEOWx7ziCCAywQ=";
  ldflags = [ "-s" "-w" ];
  meta = {
    description = "Dynamic control-plane daemon for GRE tunnels";
    mainProgram = "gremlind";
    # GRE/netlink code is Linux-only.
    platforms = lib.platforms.linux;
  };
}
