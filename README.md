# SlopePK cross-platform project

The shared EPK1/EPK2/EPK3 extraction code has build targets for Nintendo 3DS, Nintendo DS, and PS5 homebrew.

## Nintendo 3DS / DS

Build from the project root in devkitPro MSYS2:

```sh
export DEVKITARM="$DEVKITPRO/devkitARM"
make 3ds
make ds
```

Outputs: `targets/3ds/slopepk_3ds.3dsx` and `targets/ds/slopepk_ds.nds`.

## PS5 homebrew

Requires a legally obtained and installed PS5 Payload SDK / Prospero toolchain. This target builds a command-line ELF; it does not package or install it as a PS5 application, and it has not been tested on a console.

```sh
export PS5_PAYLOAD_SDK=/path/to/ps5-payload-sdk
make ps5
```

Output: `targets/ps5/slopepk_ps5.elf`.

The PS5 frontend accepts input and output paths as arguments where your payload launcher supports arguments:

```sh
slopepk_ps5.elf /data/slopepk/input.epk /data/slopepk/output
```

Defaults are `/data/slopepk/input.epk` and `/data/slopepk/output`; the log is written to `/data/slopepk/slopepk.log`. Make sure the paths are accessible in the homebrew runtime. This is a CLI port, not a controller-driven PS5 UI/file picker.

The PS5 target has not been compiled against a local PS5 SDK. The Nintendo targets also require their respective devkitPro SDKs.
