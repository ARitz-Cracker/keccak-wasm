const{InitializeKeccakLib, Keccak, keccak224, keccak256, keccak384, keccak512} = require("./keccak.js");
/* istanbul ignore next */
const InitializeKeccak = (bytes) => {
	if(bytes == null){
		return new Promise((resolve, reject) => {
			require("fs").readFile(__dirname + "/bin/keccak.wasm", (err, data) => {
				if(err){
					reject(err);
				}else{
					resolve(InitializeKeccakLib(data));
				}
			});
		});
	}
	return InitializeKeccakLib(bytes);
};
module.exports = {InitializeKeccak, Keccak, keccak224, keccak256, keccak384, keccak512};
