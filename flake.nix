{
  description = "A very basic flake";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
  };

  outputs = { nixpkgs, ... }:
  let
    system = "x86_64-linux";
    buildInputs = [ pkgs.openssl ];
    redit = (pkgs.rustPlatform.buildRustPackage {
      name = "redit";
      src = ./.;
      cargoLock = {
        lockFile = ./Cargo.lock;
      };
      nativeBuildInputs = with pkgs; [
        rustPlatform.bindgenHook
        pkg-config
      ];
      inherit buildInputs;
    });
    pkgs = import nixpkgs {
      inherit system;
      overlays = [
        (final: prev: {
          inherit redit;
        })
      ];
    };
  in
  {
    devShells.${system}.default = pkgs.mkShell {
      buildInputs = buildInputs ++ (with pkgs; [
        cargo
        rustc
        pkg-config
      ]);
    };
    packages.x86_64-linux.default = redit;
  };
}
