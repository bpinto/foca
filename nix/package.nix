# foca for Linux, built like scripts/build-linux.sh: no cgo, no test code.
{ lib, buildGoModule, src }:

buildGoModule {
  pname = "foca";
  version = "0.1.0-dev";
  src = lib.fileset.toSource {
    root = src;
    fileset = lib.fileset.unions [ (src + "/go.mod") (src + "/go.sum") (src + "/cmd") (src + "/internal") ];
  };
  # Update after changing go.mod: set lib.fakeHash, build, copy the hash it prints.
  vendorHash = "sha256-g3ncJiNAwgujJVkBigW2lbhy5Z2Ze27sHHoF9glBfiU=";
  subPackages = [ "cmd/foca" ];
  env.CGO_ENABLED = "0";
  ldflags = [ "-s" "-w" "-X main.version=0.1.0-dev+nix" ];
  # CI runs the tests; many need dbus, polkitd or swtpm, which the build
  # sandbox doesn't have.
  doCheck = false;
  meta = {
    description = "Approval-gated credentials for processes, VMs and containers";
    homepage = "https://github.com/bpinto/foca";
    license = lib.licenses.mit;
    mainProgram = "foca";
    platforms = lib.platforms.linux;
  };
}
