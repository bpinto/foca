# A user's foca: the config, written from Nix (design §7) and checked by foca
# itself at build time, and the services: systemd user units on Linux, launchd
# agents on macOS.
self:
{ config, lib, pkgs, ... }:

let
  cfg = config.services.foca;
  toml = pkgs.formats.toml { };
  foca = lib.getExe cfg.package;

  # A config foca refuses fails the build, with foca's own error.
  configFile = pkgs.runCommand "foca-config.toml" { } ''
    cp ${toml.generate "foca-config.toml" ({ version = 1; } // cfg.settings)} $out
    ${foca} config check $out
  '';
in
{
  options.services.foca = {
    enable = lib.mkEnableOption "the foca service for this user";

    package = lib.mkOption {
      type = lib.types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.foca;
      defaultText = lib.literalExpression "foca.packages.\${system}.foca";
      description = "The foca package.";
    };

    settings = lib.mkOption {
      type = toml.type;
      default = { };
      example = lib.literalExpression ''
        {
          plugins = { authenticator = "polkit"; key_protector = "tpm"; };
          vaults.common = { };
          instances.dev = { realm.kind = "vm"; expose = [ "dev:*" "common:github-pat" ]; };
        }
      '';
      description = ''
        foca's config.toml (design §7), without `version`, which is added. It is
        checked by foca when the configuration is built.

        The file is in the Nix store, which every local user can read. Never put
        a secret in it: an action's `env` values are written there as they are,
        so a secret an action needs belongs in the vault, named by `env_secrets`.
      '';
    };

    processes = lib.mkOption {
      type = lib.types.attrsOf (lib.types.listOf lib.types.str);
      default = { foca = [ ]; };
      example = { foca-vms = [ "dev" "work" ]; foca-web = [ "web" ]; };
      description = ''
        The services to run, by systemd unit or launchd agent name, each
        serving the instances listed (`foca serve --only`), or every instance
        when the list is empty.
        Instances that read a vault in common must be in one service.
      '';
    };
  };

  config = lib.mkIf cfg.enable (lib.mkMerge [
    {
      home.packages = [ cfg.package ];
      xdg.configFile."foca/config.toml".source = configFile;
    }

    (lib.mkIf pkgs.stdenv.hostPlatform.isLinux {
      systemd.user.services = lib.mapAttrs (name: only: {
        Unit = {
          Description = "foca credential service" + lib.optionalString (only != [ ]) " (${lib.concatStringsSep ", " only})";
          # A new config restarts the service; `foca reload` keeps it running.
          X-Restart-Triggers = [ "${configFile}" ];
        };
        Service = {
          ExecStart = lib.concatStringsSep " " ([ foca "serve" ] ++ lib.concatMap (i: [ "--only" (lib.escapeShellArg i) ]) only);
          ExecReload = "${pkgs.coreutils}/bin/kill -HUP $MAINPID";
          Restart = "on-failure";
          # Hardening that leaves what foca needs: the session D-Bus and the
          # system bus (polkit), /dev/tpmrm0, the runtime directory, and
          # actions, which may need the network and the user's home. No
          # MemoryDenyWriteExecute: actions inherit it, and a JIT runtime
          # (node, java) can't run under it. Under NoNewPrivileges an action
          # can't gain privileges through a setuid program such as sudo.
          NoNewPrivileges = true;
          LockPersonality = true;
          RestrictSUIDSGID = true;
          RestrictRealtime = true;
          SystemCallArchitectures = "native";
          UMask = "0077";
        };
        Install.WantedBy = [ "default.target" ];
      }) cfg.processes;
    })

    (lib.mkIf pkgs.stdenv.hostPlatform.isDarwin {
      launchd.agents = lib.mapAttrs (name: only: {
        enable = true;
        # The user's GUI session, where Touch ID can prompt.
        domain = "gui";
        config = {
          # The config this generation built, named in the agent so that a
          # new config changes the agent and home-manager restarts it.
          ProgramArguments = [ foca "--config" "${configFile}" "serve" ] ++ lib.concatMap (i: [ "--only" i ]) only;
          RunAtLoad = true;
          # Restarted when it fails, as on Linux; `foca stop` stops it.
          KeepAlive.SuccessfulExit = false;
          Umask = 63; # 0077
          StandardErrorPath = "${config.home.homeDirectory}/Library/Logs/${name}.log";
        };
      }) cfg.processes;
    })
  ]);
}
