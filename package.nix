{
  lib,
  stdenvNoCC,
  fetchurl,
  dpkg,
  patchelf,
  glibc,
}:

stdenvNoCC.mkDerivation (finalAttrs: {
  pname = "vanta-agent";
  version = "2.20.0";

  # Versioned URL from Vanta's update repository; old releases stay available
  # there, so a pin keeps building after Vanta ships a new version. See the
  # README for how to bump it.
  src = fetchurl {
    url = "https://agent-downloads.vanta.com/targets/versions/${finalAttrs.version}/vanta-amd64.deb";
    hash = "sha256-QuZ+K4dXI5YZ8qKqgJPcMrkbiKpFwtFThjYJf8S2PaY=";
  };

  nativeBuildInputs = [
    dpkg
    patchelf
  ];

  unpackPhase = ''
    runHook preUnpack
    dpkg-deb -x "$src" .
    runHook postUnpack
  '';

  dontConfigure = true;
  dontBuild = true;

  # We patch the one dynamic binary by hand below; the four Go binaries are
  # fully static, so keep the generic ELF fixups out of the way.
  dontPatchELF = true;
  dontStrip = true;

  installPhase = ''
    runHook preInstall

    mkdir -p "$out/libexec/vanta"
    cp -r var/vanta/. "$out/libexec/vanta/"

    # osqueryd is the only dynamically-linked binary. It bakes in the FHS
    # interpreter /lib64/ld-linux-x86-64.so.2, which does not exist on NixOS,
    # and needs libc/libdl/libm/libpthread/librt/libresolv -- all from glibc.
    patchelf \
      --set-interpreter "${glibc}/lib/ld-linux-x86-64.so.2" \
      --set-rpath "${lib.makeLibraryPath [ glibc ]}" \
      "$out/libexec/vanta/osqueryd"

    runHook postInstall
  '';

  meta = {
    description = "Vanta Device Monitor agent (repackaged from the upstream .deb)";
    homepage = "https://vanta.com";
    sourceProvenance = [ lib.sourceTypes.binaryNativeCode ];
    license = lib.licenses.unfree;
    platforms = [ "x86_64-linux" ]; # upstream ships an amd64 .deb only
    mainProgram = "vanta-cli";
  };
})
