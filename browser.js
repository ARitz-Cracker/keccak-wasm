const{InitializeKeccakLib, Keccak, keccak224, keccak256, keccak384, keccak512} = require("./keccak.js");
const InitializeKeccak = async(bytes) => {
	if(bytes == null){
		const response = await fetch(__dirname + "/bin/keccak.wasm");
		if(response.ok){
			return InitializeKeccakLib(new Uint8Array(response.arrayBuffer()));
		}
		throw new Error("Failed to load keccak binary: " + response.status + " " + response.statusText);
	}else{
		return InitializeKeccakLib(bytes);
	}
};
module.exports = {InitializeKeccak, Keccak, keccak224, keccak256, keccak384, keccak512};
