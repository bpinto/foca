# `nix flake check`: the package builds, and the modules produce what foca
# needs. The modules are checked by evaluating them; nothing here needs a VM.
{ self, pkgs, darwinPkgs, home-manager }:

let
  lib = pkgs.lib;
  system = pkgs.stdenv.hostPlatform.system;

  host = (pkgs.nixos {
    imports = [ self.nixosModules.default ];
    services.foca = { enable = true; users = [ "alice" ]; };
    users.users.alice.isNormalUser = true;
  }).config;

  guest = sysctl: (pkgs.nixos {
    imports = [ self.nixosModules.guest ];
    services.foca-guest.enable = true;
    boot.kernel.sysctl = sysctl;
  }).config;

  homeOn = pkgs: module: (home-manager.lib.homeManagerConfiguration {
    inherit pkgs;
    modules = [ self.homeManagerModules.default module ];
  }).config;

  user = settings: homeOn pkgs {
    home = { username = "alice"; homeDirectory = "/home/alice"; stateVersion = "25.05"; };
    services.foca = {
      enable = true;
      inherit settings;
      processes = { foca-vms = [ "dev" "work" ]; foca-web = [ "web" ]; };
    };
  };

  # A Mac, evaluated here. A stand-in package: a Mac build can't run on Linux.
  mac = homeOn darwinPkgs {
    home = { username = "alice"; homeDirectory = "/Users/alice"; stateVersion = "25.05"; };
    services.foca = {
      enable = true;
      package = darwinPkgs.writeShellScriptBin "foca" "";
      settings = settings // { plugins = { authenticator = "touchid"; key_protector = "keychain"; }; };
      processes = { foca-vms = [ "dev" "work" ]; };
    };
  };
  macAgent = mac.launchd.agents.foca-vms;

  settings = {
    plugins = { authenticator = "polkit"; key_protector = "tpm"; };
    vaults.common = { };
    instances = {
      dev = { realm.kind = "vm"; expose = [ "dev:*" "common:github-pat" ]; };
      work = { realm.kind = "vm"; expose = [ "common:*" ]; };
      web = { realm = { kind = "container"; peers = "direct"; }; };
    };
  };
  alice = user settings;
  # Only foca's own assertions: a bare test system fails others (no boot loader).
  failed = assertions: lib.any (a: !a.assertion && lib.hasPrefix "foca-guest" a.message) assertions;
in
{
  foca = self.packages.${system}.foca;

  # The polkit action names the users as owners; they get the TPM.
  nixos-host =
    assert lib.elem "tss" host.users.users.alice.extraGroups;
    assert host.security.tpm2.enable && host.security.polkit.enable;
    assert host.boot.kernel.sysctl."kernel.yama.ptrace_scope" == 1;
    assert lib.elem self.packages.${system}.foca host.environment.systemPackages;
    pkgs.runCommand "foca-check-nixos-host" { } ''
      grep -q 'org.freedesktop.policykit.owner">unix-user:alice<' \
        ${host.environment.etc."polkit-1/actions/io.github.bpinto.foca.policy".source}
      touch $out
    '';

  # ptrace_scope is at least 1, and a config that lowers it is refused.
  nixos-guest =
    assert (guest { })."boot".kernel.sysctl."kernel.yama.ptrace_scope" == 1;
    assert !failed (guest { "kernel.yama.ptrace_scope" = 2; }).assertions;
    assert failed (guest { "kernel.yama.ptrace_scope" = 0; }).assertions;
    pkgs.runCommand "foca-check-nixos-guest" { } "touch $out";

  # The config is foca's, checked by foca; one service per process group.
  home-manager =
    assert lib.hasSuffix "serve --only dev --only work" (toString alice.systemd.user.services.foca-vms.Service.ExecStart);
    assert lib.hasSuffix "serve --only web" (toString alice.systemd.user.services.foca-web.Service.ExecStart);
    assert alice.systemd.user.services.foca-vms.Service.NoNewPrivileges && alice.systemd.user.services.foca-vms.Service.UMask == "0077";
    pkgs.runCommand "foca-check-home-manager" { } ''
      grep -q 'expose = \["dev:\*", "common:github-pat"\]' ${alice.xdg.configFile."foca/config.toml".source}
      touch $out
    '';

  # A config foca refuses fails the build, with foca's message.
  home-manager-bad-config =
    let
      bad = user (settings // { instances.dev = { realm.kind = "vm"; expose = [ "github-pat" ]; }; });
      log = pkgs.testers.testBuildFailure bad.xdg.configFile."foca/config.toml".source;
    in
    pkgs.runCommand "foca-check-home-manager-bad-config" { } ''
      grep -q 'expose: "github-pat" must be' ${log}/testBuildFailure.log
      touch $out
    '';

  # On a Mac: launchd agents in the GUI session instead of systemd units, each
  # started with the config its generation built, so a new config restarts it.
  home-manager-darwin =
    let args = macAgent.config.ProgramArguments; in
    assert macAgent.enable && macAgent.domain == "gui";
    assert lib.take 3 args == [ "${lib.getExe mac.services.foca.package}" "--config" "${mac.xdg.configFile."foca/config.toml".source}" ];
    assert lib.drop 3 args == [ "serve" "--only" "dev" "--only" "work" ];
    assert macAgent.config.RunAtLoad && macAgent.config.KeepAlive.SuccessfulExit == false;
    assert macAgent.config.Umask == 63;
    assert !(mac.systemd.user.services ? foca-vms) && !(alice.launchd.agents ? foca-vms);
    pkgs.runCommand "foca-check-home-manager-darwin" { } "touch $out";
}
