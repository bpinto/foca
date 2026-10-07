{
  description = "foca: approval-gated credential service";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "aarch64-linux" "x86_64-linux" "aarch64-darwin" "x86_64-darwin" ];
      forAll = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in {
      devShells = forAll (pkgs: {
        default = pkgs.mkShell {
          packages = [ pkgs.go pkgs.gopls pkgs.socat pkgs.gcc pkgs.dbus ];  # gcc: only for `go test -race`; dbus: logind tests
          CGO_ENABLED = "0";
        };
      });
    };
}
