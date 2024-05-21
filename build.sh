#!/bin/sh
if [ "$(wasm-pack --version)" != "wasm-pack 0.12.1" ]; then
	echo "wasm-pack isn't installed or isn't 0.12.1";
	echo "This script modifies the output to be completely cross-platform, compatibility with other versions is not guaranteed.";
	exit 1;
fi;
set -e;
cd "$(dirname "$0")";
rm -rf pkg;
wasm-pack build --target web; # Build in web mode, target is closest to a true "cross-platform" output (Native-Web, Node, and Webpack)

# This file is useless
rm ./pkg/keccak_wasm_bg.wasm.d.ts; 

# Create importable binary
echo "// I'm sorry for inflating the size of the binary by 33%, but this is the only way I could quickly get this working with Webpack and NodeJS at the same time. Please forgive me." > ./pkg/keccak_wasm_bg.wasm.js;
echo "const WASM_BASE64 = \"$(base64 -w 0 ./pkg/keccak_wasm_bg.wasm)\";" >> ./pkg/keccak_wasm_bg.wasm.js;
echo "export const WASM_BINARY = typeof Buffer != \"undefined\" ? Buffer.from(WASM_BASE64, \"base64\") : new Uint8Array([...atob(WASM_BASE64)].map(v => v.charCodeAt(0)));" >> ./pkg/keccak_wasm_bg.wasm.js;

# Make pointers inaccessible
sed -i 's/__destroy_into_raw/#__destroy_into_raw/g' ./pkg/keccak_wasm.js;
sed -i 's/this.__wbg_ptr/this.#__wbg_ptr/g' ./pkg/keccak_wasm.js;
sed -i 's/export class KeccakHash {/export class KeccakHash {\n	#__wbg_ptr;/' ./pkg/keccak_wasm.js;

# Remove unused initSync function (Yes, I'm assuming it's 14 lines long)
sed -i '/function initSync(module) {/,+14d' ./pkg/keccak_wasm.js;

# Remove initialization functions from javascript exports 
sed -i '/export { initSync }/,+d' ./pkg/keccak_wasm.js;
sed -i '/export default __wbg_init/,+d' ./pkg/keccak_wasm.js;

# Remove initialization functions from typescript exports
sed -i '/export type InitInput/,+1000d' ./pkg/keccak_wasm.d.ts;

# Auto-load importable binary (Woo! Top-level await!)
echo "await __wbg_init(import(\"./keccak_wasm_bg.wasm.js\").then(imports => {return imports.WASM_BINARY;}));" >> ./pkg/keccak_wasm.js;

# Make the importable binary part of the npm package
sed -i 's/\"keccak_wasm_bg.wasm\"/\"keccak_wasm_bg.wasm.js\"/' ./pkg/package.json

# Add esm module type to package.json
jq ".type = \"module\"" ./pkg/package.json > ./pkg/package.json.tmp;
mv ./pkg/package.json.tmp ./pkg/package.json;
