{ lib, buildGoModule }:

buildGoModule {
  pname = "gremlind";
  version = "0.1.0";
  src = ./.;
  vendorHash = "sha256-Dhwe0At6djMzBIBmsR71XBNZYrGPQjmRWFW08SrViMo=";
  ldflags = [ "-s" "-w" ];
  meta = {
    description = "Dynamic control-plane daemon for GRE tunnels";
    mainProgram = "gremlind";
    # GRE/netlink code is Linux-only.
    platforms = lib.platforms.linux;
  };
}
