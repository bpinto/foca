# The host side of foca on NixOS: the package, foca's polkit action naming the
# users who run it (design §4.1.2), and the TPM for them (design §4.2.1).
# Each user's config and service come from the home-manager module.
self:
{ config, lib, pkgs, ... }:

let
  cfg = config.services.foca;
in
{
  options.services.foca = {
    enable = lib.mkEnableOption "foca on this host";

    package = lib.mkOption {
      type = lib.types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.foca;
      defaultText = lib.literalExpression "foca.packages.\${system}.foca";
      description = "The foca package.";
    };

    users = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      example = [ "alice" ];
      description = ''
        Users who run foca. The polkit action names them as its owners, without
        which polkit won't show foca's prompt text, and they get the TPM.
      '';
    };

    polkit = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''Install foca's polkit action, for `authenticator = "polkit"`.'';
    };

    tpm = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''Give the users the TPM (the tss group), for `key_protector = "tpm"`.'';
    };
  };

  config = lib.mkIf cfg.enable (lib.mkMerge [
    {
      assertions = [{
        assertion = cfg.users != [ ];
        message = "services.foca.users must name the users who run foca.";
      }];
      environment.systemPackages = [ cfg.package ];
      # foca hides the processes that hold vault keys itself; this keeps the
      # others, such as a `foca get` holding a value, from being attached to
      # by anything but their parents. A host that needs more can lower it.
      boot.kernel.sysctl."kernel.yama.ptrace_scope" = lib.mkDefault 1;
    }

    (lib.mkIf cfg.polkit {
      security.polkit.enable = true;
      # polkitd on NixOS reads actions from /etc/polkit-1/actions.
      environment.etc."polkit-1/actions/io.github.bpinto.foca.policy".source =
        pkgs.runCommand "io.github.bpinto.foca.policy" { } ''
          ${lib.getExe cfg.package} polkit-policy ${lib.escapeShellArgs cfg.users} > $out
        '';
    })

    (lib.mkIf cfg.tpm {
      # Its udev rules give the tss group /dev/tpmrm0.
      security.tpm2.enable = true;
      users.users = lib.genAttrs cfg.users (_: { extraGroups = [ config.security.tpm2.tssGroup ]; });
    })
  ]);
}
