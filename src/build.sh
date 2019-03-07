#!/bin/bash
if [ "$(expr substr $(uname -s) 1 10)" == "MINGW64_NT" ]; then
  # This is for when I'm on my Windows box.
  # I keep saying that I'll switch back to linux, but I never got around to it.
  source /e/emsdk/emsdk_env.sh
fi

emcc keccak.c \
  -O3 \
  -s WASM=1 \
  -s "BINARYEN_METHOD='native-wasm'" \
  -s NO_EXIT_RUNTIME=1 \
  -s DETERMINISTIC=1 \
  -s EXPORTED_FUNCTIONS='[
  "_malloc",
  "_free",
  "_keccak_new",
  "_keccak_destroy",
  "_keccak_reset",
  "_keccak_update",
  "_keccak_final"
  ]' \
  -o keccak.js &&
rm keccak.js && # For some reason specifying this output was needed to make the .wasm file
mv keccak.wasm ../bin/keccak.wasm;