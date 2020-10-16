if(typeof Buffer === "undefined"){
	try{
		require("buffer-lite");
	}catch(ex){
		// buffer-lite not installed
	}
}
const{instantiateKeccakWasmBytes} = require("./keccakWasm.js");
let keccakWasm = null;
class Keccak {
	constructor(bits){
		/* istanbul ignore next */
		if(keccakWasm == null){
			throw new Error("You must initialize this library before using it.");
		}
		this._hexLength = bits / 4;

		this._keccakInstance = keccakWasm.new(bits);
		/* istanbul ignore next */
		if(this._keccakInstance === 0){
			throw new Error("Too many Keccak objects");
		}
		this._resultPtr = keccakWasm.malloc(this._hexLength); // Output may be hex or raw
		/* istanbul ignore next */
		if(this._resultPtr === 0){
			throw new Error("Too many Keccak objects");
		}
		this._argPtr = 0;
		this._argLen = 0;
	}
	destroy(paranoia = false){
		if(this._keccakInstance === 0){
			throw new Error("Keccak instance has been destroyed");
		}
		keccakWasm.destroy(this._keccakInstance);
		if(paranoia){
			keccakWasm.heapU8.fill(0, this._argPtr, this._argPtr + this._argLen);
			keccakWasm.heapU8.fill(0, this._resultPtr, this._resultPtr + this._hexLength);
		}
		keccakWasm.free(this._argPtr);
		keccakWasm.free(this._resultPtr);
		this._argPtr = 0;
		this._argLen = 0;
		this._keccakInstance = 0;
	}
	reset(){
		if(this._keccakInstance === 0){
			throw new Error("Keccak instance has been destroyed");
		}
		keccakWasm.reset(this._keccakInstance);
	}
	update(data, paranoia = true){
		if(this._keccakInstance === 0){
			throw new Error("Keccak instance has been destroyed");
		}
		if(!(data instanceof Uint8Array)){
			if(typeof data === "string"){
				data = Buffer.from(data);
			}else{
				throw new TypeError("Must be a string or Uint8Array");
			}
		}
		// Properly handle very large inputs over 1MB in order to not run out of WASM memory
		if(data.length > 1048576){
			const argPtr = keccakWasm.malloc(1048576);
			for(let i = 0; i < data.length; i += 1048576){
				const dataSlice = data.subarray(i, i + 1048576);
				keccakWasm.heapU8.set(dataSlice, argPtr);

				keccakWasm.update(this._keccakInstance, argPtr, dataSlice.length);
			}
			if(paranoia){
				keccakWasm.heapU8.fill(0, argPtr, 1048576);
			}
			keccakWasm.free(argPtr);
		}else{
			if(data.length > this._argLen){
				keccakWasm.free(this._argPtr);
				this._argPtr = keccakWasm.malloc(data.length);
				this._argLen = data.length;
			}
			keccakWasm.heapU8.set(data, this._argPtr);
			keccakWasm.update(this._keccakInstance, this._argPtr, data.length);
			if(paranoia){
				keccakWasm.heapU8.fill(0, this._argPtr, data.length);
			}
			// 128 KB
			if(data.length > 131072){
				keccakWasm.free(this._argPtr);
				this._argPtr = 0;
				this._argLen = 0;
			}
		}
		return this;
	}
	final(hex = true, destroy = true, paranoia = false){
		if(this._keccakInstance === 0){
			throw new Error("Keccak instance has been destroyed");
		}
		keccakWasm.final(this._keccakInstance, this._resultPtr, hex, destroy);
		let result;
		if(hex){
			result = String.fromCharCode(...keccakWasm.heapU8.subarray(
				this._resultPtr, this._resultPtr + this._hexLength
			));
		}else{
			result = keccakWasm.heapU8.slice(this._resultPtr, this._resultPtr + (this._hexLength / 2));
			if(typeof Buffer !== "undefined"){
				result = Buffer.from(result.buffer, result.byteOffset, result.byteLength);
			}
		}
		if(paranoia){
			keccakWasm.heapU8.fill(0, this._argPtr, this._argPtr + this._argLen);
			keccakWasm.heapU8.fill(0, this._resultPtr, this._resultPtr + this._hexLength);
		}
		if(destroy){
			keccakWasm.free(this._argPtr);
			keccakWasm.free(this._resultPtr);
			this._argPtr = 0;
			this._argLen = 0;
			this._keccakInstance = 0;
		}
		return result;
	}
}
let initPromise;
const InitializeKeccakLib = (bytes) => {
	/* istanbul ignore next */
	if(initPromise == null){
		initPromise = (async() => {
			keccakWasm = await instantiateKeccakWasmBytes(bytes);
		})();
	}
	return initPromise;
};
const simpleFuncsInstance = [];
const simpleFuncs = [224, 256, 384, 512].map((_bits, _i) => {
	const bits = _bits;
	const i = _i;
	return function(data, hexString = true){
		let keccak = simpleFuncsInstance[i];
		if(keccak === undefined){
			keccak = new Keccak(bits);
			simpleFuncsInstance[i] = keccak;
		}
		return keccak.update(data).final(hexString, false);
	};
});

module.exports = {
	InitializeKeccakLib,
	Keccak,
	keccak224: simpleFuncs[0],
	keccak256: simpleFuncs[1],
	keccak384: simpleFuncs[2],
	keccak512: simpleFuncs[3]
};
