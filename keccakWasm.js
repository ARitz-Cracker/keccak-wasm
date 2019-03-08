/**
 * Most of this file (i.e. pretty much 99% of it) has been copied from @bitjson's secp256k1Wasm.ts in the bitcoin-ts repo on GitHub
 * You can thank that guy for getting me into WASM.
 *
 * Perhaps I should expand upon this file to make a fast generic WASM loader.
 */
/* istanbul ignore next */
const abort = function(err = "keccak Error"){
	throw new Error(err);
};

/* istanbul ignore next */
const isLittleEndian = (buffer) => {
	const littleEndian = true;
	const notLittleEndian = false;
	const heap16 = new Int16Array(buffer);
	const heap32 = new Int32Array(buffer);
	const heapU8 = new Uint8Array(buffer);
	heap32[0] = 1668509029;
	heap16[1] = 25459;
	return heapU8[2] !== 115 || heapU8[3] !== 99 ?
		notLittleEndian :
		littleEndian;
};
const alignMemory = (factor, size) => Math.ceil(size / factor) * factor;

const instantiateKeccakWasmBytes = async(bytes) => {
	const STACK_ALIGN = 16;
	const GLOBAL_BASE = 1024;
	const WASM_PAGE_SIZE = 65536;
	const TOTAL_STACK = 5242880;
	const TOTAL_MEMORY = 16777216;

	const wasmMemory = new WebAssembly.Memory({
		initial: TOTAL_MEMORY / WASM_PAGE_SIZE,
		maximum: TOTAL_MEMORY / WASM_PAGE_SIZE
	});

	/* istanbul ignore next */
	if(!isLittleEndian(wasmMemory.buffer)){
		throw new Error("Runtime error: expected the system to be little-endian.");
	}

	const STATIC_BASE = GLOBAL_BASE;
	const STATICTOP_INITIAL = STATIC_BASE + 67696 + 16;
	const DYNAMICTOP_PTR = STATICTOP_INITIAL;
	const DYNAMICTOP_PTR_SIZE = 4;

	const STATICTOP = (STATICTOP_INITIAL + DYNAMICTOP_PTR_SIZE + 15) & -16;
	const STACKTOP = alignMemory(STACK_ALIGN, STATICTOP);
	const STACK_BASE = STACKTOP;
	const STACK_MAX = STACK_BASE + TOTAL_STACK;
	const DYNAMIC_BASE = alignMemory(STACK_ALIGN, STACK_MAX);

	const heapU8 = new Uint8Array(wasmMemory.buffer);
	const heap32 = new Int32Array(wasmMemory.buffer);
	// const heapU32 = new Uint32Array(wasmMemory.buffer);
	heap32[DYNAMICTOP_PTR >> 2] = DYNAMIC_BASE;

	const TABLE_SIZE = 6;
	const MAX_TABLE_SIZE = 6;

	let getErrNoLocation;

	/* istanbul ignore next */
	const env = {
		DYNAMICTOP_PTR,
		STACKTOP,
		___setErrNo: (value) => {
			if(getErrNoLocation !== undefined){
				heap32[getErrNoLocation() >> 2] = value;
			}
			return value;
		},
		___assert_fail: (...args) => {
			let str = "keccak WASM asserstion failed:";
			for(let i = 0; i < args.length; i += 1){
				str += " " + String(args[i]);
			}
			throw new Error(str);
		},
		_emscripten_memcpy_big: (
			dest,
			src,
			num
		) => {
			heapU8.set(heapU8.subarray(src, src + num), dest);
			return dest;
		},
		_abort: abort,
		abortOnCannotGrowMemory: () => {
			throw new Error("keccak Error: abortOnCannotGrowMemory was called.");
		},
		enlargeMemory: () => {
			throw new Error("keccak Error: enlargeMemory was called.");
		},
		getTotalMemory: () => TOTAL_MEMORY
	};

	const info = {
		env: {
			...env,
			memory: wasmMemory,
			memoryBase: STATIC_BASE,
			table: new WebAssembly.Table({
				element: "anyfunc",
				initial: TABLE_SIZE,
				maximum: MAX_TABLE_SIZE
			}),
			tableBase: 0
		},
		global: {NaN, Infinity}
	};
	const result = await WebAssembly.instantiate(bytes, info);
	const exports = result.instance.exports;
	return {
		heapU8,
		malloc: exports._malloc,
		free: exports._free,
		new: (bits) => exports._keccak_new(bits),
		destroy: (instance) => {
			exports._keccak_destroy(instance);
		},
		reset: (instance) => {
			exports._keccak_reset(instance);
		},
		update: (instance, dataPtr, dataLen) => {
			exports._keccak_update(instance, dataPtr, dataLen);
		},
		final: (instance, hex, destroy) => {
			exports._keccak_final(instance, hex, destroy);
		}
	};
};

module.exports = {instantiateKeccakWasmBytes};
