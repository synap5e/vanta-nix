{
  description = "Vanta Device Monitor agent, packaged for NixOS";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" ]; # upstream ships an amd64 .deb only
      forAllSystems = nixpkgs.lib.genAttrs systems;
      # Allow just this one unfree package, so the flake's own outputs build
      # without NIXPKGS_ALLOW_UNFREE. NixOS configurations importing the module
      # still have to allow it themselves.
      pkgsFor =
        system:
        import nixpkgs {
          inherit system;
          overlays = [ self.overlays.default ];
          config.allowUnfreePredicate = pkg: nixpkgs.lib.getName pkg == "vanta-agent";
        };
    in
    {
      packages = forAllSystems (system: rec {
        inherit (pkgsFor system) vanta-agent;
        default = vanta-agent;
      });

      overlays.default = final: _prev: {
        vanta-agent = final.callPackage ./package.nix { };
      };

      nixosModules.vanta = {
        imports = [ ./module.nix ];
        nixpkgs.overlays = [ self.overlays.default ];
      };
      nixosModules.default = self.nixosModules.vanta;

      checks = forAllSystems (system: {
        inherit (self.packages.${system}) vanta-agent;
        # Boots a VM with no network access; the agent never reaches Vanta.
        vm = (pkgsFor system).testers.runNixOSTest (import ./tests/vm.nix);
      });

      formatter = forAllSystems (system: nixpkgs.legacyPackages.${system}.nixfmt);
    };
}
