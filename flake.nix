{
  description = "foca: approval-gated credential service";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    # Only the checks of the home-manager module use it.
    home-manager = {
      url = "github:nix-community/home-manager";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, home-manager }:
    let
      lib = nixpkgs.lib;
      systems = [ "aarch64-linux" "x86_64-linux" "aarch64-darwin" "x86_64-darwin" ];
      linux = [ "aarch64-linux" "x86_64-linux" ];
      forAll = systems: f: lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in {
      # Built from source on Linux. On macOS foca must be built by
      # scripts/build-darwin.sh, which signs foca-darwin and pins its hash into
      # foca (design §5), so the package is the release archive.
      packages = forAll linux (pkgs: rec {
        foca = pkgs.callPackage ./nix/package.nix { src = ./.; };
        default = foca;
      }) // forAll [ "aarch64-darwin" ] (pkgs: rec {
        foca = pkgs.callPackage ./nix/darwin.nix { };
        default = foca;
      });

      # The host: the package, foca's polkit action and the TPM for its users.
      nixosModules.default = import ./nix/nixos.nix self;
      # A user's config and services: systemd on Linux, launchd on macOS.
      homeManagerModules.default = import ./nix/home.nix self;

      checks = forAll linux (pkgs: import ./nix/checks.nix {
        inherit self pkgs home-manager;
        darwinPkgs = nixpkgs.legacyPackages.aarch64-darwin;
      });

      devShells = forAll systems (pkgs: {
        default = pkgs.mkShell ({
          # gcc: only for `go test -race`; dbus: logind and polkit tests;
          # bubblewrap: runs the real polkitd in the polkit tests; swtpm: the
          # software TPM the TPM key protector tests run against
          packages = [ pkgs.go pkgs.gopls pkgs.socat pkgs.gcc pkgs.dbus ]
            ++ lib.optionals pkgs.stdenv.hostPlatform.isLinux [ pkgs.bubblewrap pkgs.swtpm ];
          CGO_ENABLED = "0";
        } // lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
          FOCA_POLKITD = "${pkgs.polkit.out}/lib/polkit-1/polkitd";
          FOCA_SWTPM = "${pkgs.swtpm}/bin/swtpm";
        });
      });
    };
}
