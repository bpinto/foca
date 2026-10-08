{
  description = "foca: approval-gated credential service";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "aarch64-linux" "x86_64-linux" "aarch64-darwin" "x86_64-darwin" ];
      forAll = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in {
      devShells = forAll (pkgs: {
        default = pkgs.mkShell ({
          # gcc: only for `go test -race`; dbus: logind and polkit tests;
          # bubblewrap: runs the real polkitd in the polkit tests; swtpm: the
          # software TPM the TPM key protector tests run against
          packages = [ pkgs.go pkgs.gopls pkgs.socat pkgs.gcc pkgs.dbus ]
            ++ nixpkgs.lib.optionals pkgs.stdenv.hostPlatform.isLinux [ pkgs.bubblewrap pkgs.swtpm ];
          CGO_ENABLED = "0";
        } // nixpkgs.lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
          FOCA_POLKITD = "${pkgs.polkit.out}/lib/polkit-1/polkitd";
          FOCA_SWTPM = "${pkgs.swtpm}/bin/swtpm";
        });
      });
    };
}
