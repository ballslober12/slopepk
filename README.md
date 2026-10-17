slopepk extracts only epk2 for now

## Nintendo 3DS / DS


```sh
export DEVKITARM="$DEVKITPRO/devkitARM"
make 3ds
make ds
```

Outputs: `targets/3ds/slopepk_3ds.3dsx` and `targets/ds/slopepk_ds.nds`.

## PS5

```sh
export PS5_PAYLOAD_SDK=/path/to/ps5-payload-sdk
make ps5
```

Output: `targets/ps5/slopepk_ps5.elf`.

to run

```sh
slopepk_ps5.elf /data/slopepk/input.epk /data/slopepk/output
```

Defaults are `/data/slopepk/input.epk` and `/data/slopepk/output`; the log is written to `/data/slopepk/slopepk.log`. Make sure the paths are 
poopy poop poop poop 

i didint tested ps5 so uhh try by urself 
