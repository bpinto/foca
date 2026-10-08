# foca for macOS: the release archive, installed as it is. foca-darwin is
# signed, and foca runs it only if its sha256 matches the pin built into foca
# (design §5), so nothing here may strip, patch or re-sign either binary.
{ lib, stdenvNoCC, fetchurl }:

let
  release = import ./darwin-release.nix;
in
assert lib.assertMsg (release.hash != null)
  "foca: nix/darwin-release.nix pins no release yet, so there is no macOS package";
stdenvNoCC.mkDerivation {
  pname = "foca";
  inherit (release) version;
  src = fetchurl {
    url = "https://github.com/bpinto/foca/releases/download/v${release.version}/foca-darwin-arm64.tar.gz";
    inherit (release) hash;
  };
  # The archive has no top-level directory.
  sourceRoot = ".";
  dontConfigure = true;
  dontBuild = true;
  # Fixup strips binaries and signs them again, which would change
  # foca-darwin and break its pin.
  dontFixup = true;
  installPhase = ''
    runHook preInstall
    install -Dm755 -t $out/bin foca foca-darwin
    runHook postInstall
  '';
  meta = {
    description = "Approval-gated credentials for processes, VMs and containers";
    homepage = "https://github.com/bpinto/foca";
    license = lib.licenses.mit;
    mainProgram = "foca";
    platforms = [ "aarch64-darwin" ];
    sourceProvenance = [ lib.sourceTypes.binaryNativeCode ];
  };
}
