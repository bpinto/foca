# A VM (or container host) whose processes reach foca through a forwarded
# socket: the client, the hardening design §14 asks of a realm, and the
# optional guest relay.
self:
{ config, lib, pkgs, ... }:

let
  cfg = config.services.foca-guest;
  relay = cfg.relay;
  ptraceScope = config.boot.kernel.sysctl."kernel.yama.ptrace_scope";
  foca = lib.getExe cfg.package;
  nologin = "${pkgs.shadow}/bin/nologin";
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

    relay = {
      enable = lib.mkEnableOption ''
        the guest relay (design §14). The host's ssh logs in as the relay's
        user to forward its socket, which only that user can reach; the
        relay reads each caller from this kernel and vouches for it. Set the
        instance's guest_relay on the host to the key `foca relay pubkey`
        prints as this user'';

      user = lib.mkOption {
        type = lib.types.str;
        default = "foca";
        description = "The relay's own user, which the host's ssh logs in as for the forward.";
      };

      home = lib.mkOption {
        type = lib.types.str;
        default = "/var/lib/foca-relay";
        description = "The relay user's home (0700): the forwarded socket and the key live there.";
      };

      upstream = lib.mkOption {
        type = lib.types.str;
        default = "${relay.home}/.foca.sock";
        defaultText = lib.literalExpression ''"''${home}/.foca.sock"'';
        description = "Where the host's ssh forwards foca's socket (ssh -N -R <this>:<client.sock>).";
      };

      socket = lib.mkOption {
        type = lib.types.str;
        default = "/run/foca/relay.sock";
        description = "The socket this VM's processes use; FOCA_SOCK points at it.";
      };

      keyFile = lib.mkOption {
        type = lib.types.str;
        default = "${relay.home}/relay.key";
        defaultText = lib.literalExpression ''"''${home}/relay.key"'';
        description = "The relay's private key, made on first start.";
      };

      maxConnections = lib.mkOption {
        type = lib.types.ints.between 1 1024;
        default = 32;
        description = "Callers the relay serves at once.";
      };

      maxPerUser = lib.mkOption {
        type = lib.types.ints.between 1 1024;
        default = 8;
        description = ''
          Callers of one uid the relay serves at once, so one user of the
          VM can't take every connection the host's max_connections allows.
        '';
      };

      authorizedKeys = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [ ];
        description = "ssh public keys the host forwards the socket with.";
      };
    };
  };

  config = lib.mkIf cfg.enable (lib.mkMerge [
    {
      environment.systemPackages = [ cfg.package ];
      # A process can't attach to another session's process and borrow what it
      # was approved for. Higher values are stricter and fine too.
      boot.kernel.sysctl."kernel.yama.ptrace_scope" = lib.mkDefault 1;
      assertions = [{
        assertion = ptraceScope >= 1;
        message = "foca-guest needs kernel.yama.ptrace_scope of 1 or more (got ${toString ptraceScope}).";
      }];
    }

    (lib.mkIf relay.enable {
      users.users.${relay.user} = {
        isSystemUser = true;
        group = relay.user;
        home = relay.home;
        createHome = true;
        homeMode = "700";
        # Only the forward: no shell, no terminal.
        shell = nologin;
        openssh.authorizedKeys.keys = relay.authorizedKeys;
      };
      users.groups.${relay.user} = { };

      # The forwarded socket is the relay user's alone (0600), so the VM's
      # other users can reach foca only through the relay.
      services.openssh.extraConfig = ''
        Match User ${relay.user}
          StreamLocalBindMask 0177
          StreamLocalBindUnlink yes
          AllowStreamLocalForwarding remote
          AllowTcpForwarding no
          AllowAgentForwarding no
          X11Forwarding no
          PermitTTY no
          ForceCommand ${nologin}
      '';

      environment.variables.FOCA_SOCK = relay.socket;

      systemd.services.foca-relay = {
        description = "foca guest relay";
        wantedBy = [ "multi-user.target" ];
        after = [ "network.target" ];
        serviceConfig = {
          User = relay.user;
          Group = relay.user;
          ExecStartPre = pkgs.writeShellScript "foca-relay-key" ''
            [ -e ${lib.escapeShellArg relay.keyFile} ] || ${foca} relay keygen --key-file ${lib.escapeShellArg relay.keyFile}
          '';
          ExecStart = lib.escapeShellArgs [
            foca "relay" "serve" "--listen" relay.socket "--upstream" relay.upstream "--key-file" relay.keyFile
            "--max-connections" (toString relay.maxConnections) "--max-per-user" (toString relay.maxPerUser)
          ];
          RuntimeDirectory = "foca";
          RuntimeDirectoryMode = "0755";
          # None: the relay reads only what /proc shows every user. Reading
          # other users' programs would need CAP_SYS_PTRACE, which would let
          # whoever takes over this user read any process in the VM.
          CapabilityBoundingSet = "";
          NoNewPrivileges = true;
          ProtectSystem = "strict";
          ReadWritePaths = [ relay.home ];
          # The relay parses every VM user's input, so it gets little else.
          # It must still see every process in /proc (no ProtectProc,
          # ProcSubset or PrivateUsers, which would hide callers or their
          # uids), reach the forwarded socket in its home and make its own
          # under /run/foca. Unix sockets with a path work across network
          # namespaces, so PrivateNetwork costs it nothing.
          PrivateNetwork = true;
          RestrictAddressFamilies = [ "AF_UNIX" ];
          SystemCallFilter = [ "@system-service" ];
          SystemCallArchitectures = "native";
          ProtectKernelTunables = true;
          ProtectKernelModules = true;
          ProtectKernelLogs = true;
          ProtectControlGroups = true;
          ProtectClock = true;
          ProtectHostname = true;
          LockPersonality = true;
          MemoryDenyWriteExecute = true;
          RestrictNamespaces = true;
          RestrictRealtime = true;
          RestrictSUIDSGID = true;
          PrivateTmp = true;
          PrivateDevices = true;
          UMask = "0077";
          Restart = "always";
          RestartSec = 1;
        };
      };
    })
  ]);
}
