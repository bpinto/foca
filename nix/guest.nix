# A VM (or container host) whose processes reach foca through a forwarded
# socket: the client, and the hardening design §14 asks of a realm.
self:
{ config, lib, pkgs, ... }:

let
  cfg = config.services.foca-guest;
  ptraceScope = config.boot.kernel.sysctl."kernel.yama.ptrace_scope";
in
{
  options.services.foca-guest = {
    enable = lib.mkEnableOption "the foca client in this VM";

    package = lib.mkOption {
      type = lib.types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.foca;
      defaultText = lib.literalExpression "foca.packages.\${system}.foca";
      description = "The foca package.";
    };
  };

  config = lib.mkIf cfg.enable {
    environment.systemPackages = [ cfg.package ];
    # A process can't attach to another session's process and borrow what it
    # was approved for. Higher values are stricter and fine too.
    boot.kernel.sysctl."kernel.yama.ptrace_scope" = lib.mkDefault 1;
    assertions = [{
      assertion = ptraceScope >= 1;
      message = "foca-guest needs kernel.yama.ptrace_scope of 1 or more (got ${toString ptraceScope}).";
    }];
  };
}
