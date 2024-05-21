use bytemuck::{cast_slice, cast_slice_mut, try_cast_slice, Zeroable};
use wasm_bindgen::prelude::*;
/*
	This file is adapted from keccak.cpp and keccak.h by Stephan Brumme
	Modified and redistributed by Aritz Beobide-Cardinal following his "similar to the zlib license" license
	The original software can be found here: https://create.stephan-brumme.com/hash-library/
	The "similar to the zlib license" license can be found at: https://create.stephan-brumme.com/disclaimer.html
	Copyright (c) 2014,2015 Stephan Brumme
	Copyright (c) 2019,2024 Aritz Beobide-Cardinal
*/

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum KeccakBits {
	Keccak224 = 224,
	Keccak256 = 256,
	Keccak384 = 384,
	Keccak512 = 512
}

impl KeccakBits {
	pub const fn byte_len(&self) -> usize {
		*self as usize / 8
	}
	pub const fn block_size_bytes(&self) -> usize {
		200 - 2 * ((*self as u16) as usize / 8)
	}
	pub const fn block_size_u64(&self) -> usize {
		self.block_size_bytes() / 8
	}
}
impl TryFrom<u32> for KeccakBits {
	type Error = JsError;
	fn try_from(value: u32) -> Result<Self, Self::Error> {
		match value {
			224 => Ok(KeccakBits::Keccak224),
			256 => Ok(KeccakBits::Keccak256),
			384 => Ok(KeccakBits::Keccak384),
			512 => Ok(KeccakBits::Keccak512),
			_ => Err(JsError::new("KeccakBits must be 224, 256, 384, or 512."))
		}
	}
}


/// 1600 bits, stored as 25x64 bit
const HASH_STATE_SIZE: usize = 1600 / (8 * 8);
/// Keccak224 has the largest blocksize 
const MAX_BLOCK_SIZE_U64: usize = KeccakBits::Keccak224.block_size_u64();

const KECCAK_ROUNDS: usize = 24;
const XOR_MASKS: [u64; KECCAK_ROUNDS] = [
	0x0000000000000001u64, 0x0000000000008082u64, 0x800000000000808au64,
	0x8000000080008000u64, 0x000000000000808bu64, 0x0000000080000001u64,
	0x8000000080008081u64, 0x8000000000008009u64, 0x000000000000008au64,
	0x0000000000000088u64, 0x0000000080008009u64, 0x000000008000000au64,
	0x000000008000808bu64, 0x800000000000008bu64, 0x8000000000008089u64,
	0x8000000000008003u64, 0x8000000000008002u64, 0x8000000000000080u64,
	0x000000000000800au64, 0x800000008000000au64, 0x8000000080008081u64,
	0x8000000000008080u64, 0x0000000080000001u64, 0x8000000080008008u64
];

#[derive(Debug, Clone, Copy)]
#[wasm_bindgen]
pub struct KeccakHash {
	hash_state: [u64; HASH_STATE_SIZE],
	// block_buffer of type u64 so that allignment works
	block_buffer: [u64; MAX_BLOCK_SIZE_U64],
	block_buffer_byte_len: usize,
	bits: KeccakBits,
}


#[wasm_bindgen]
impl KeccakHash {
	#[wasm_bindgen(constructor)]
	/// Creates a new KeccakHash instance.
	/// 
	/// **You must call the `.free()` method when you're done using this if you're not using the `.final_digest()` or
	/// `.final_digest_hex()` methods.**
	/// 
	/// bits must be must be 224, 256, 384, or 512. If they aren't, an error will be thrown.
	pub fn new(bits: u32) -> Result<KeccakHash, JsError> {
		Ok(
			KeccakHash {
				hash_state: Zeroable::zeroed(),
				block_buffer: Zeroable::zeroed(),
				block_buffer_byte_len: 0,
				bits: bits.try_into()?
			}
		)
	}
	fn new_with_bits(bits: KeccakBits) -> KeccakHash {
		KeccakHash {
			hash_state: Zeroable::zeroed(),
			block_buffer: Zeroable::zeroed(),
			block_buffer_byte_len: 0,
			bits
		}
	}
	pub fn test_hash_state(&self) -> Vec<u8> {
		Vec::from(cast_slice::<_, u8>(&self.hash_state))
	}

	/// Adds bytes to the hash
	pub fn update(&mut self, mut bytes: &[u8]) {
		let block_size_bytes = self.bits.block_size_bytes();
		let block_size_u64 = self.bits.block_size_u64();
		let block_buffer_u64 = &mut self.block_buffer[0..block_size_u64];
		
		// Fill the block buffer if we can
		if self.block_buffer_byte_len > 0 {
			let block_buffer_bytes = cast_slice_mut::<_, u8>(block_buffer_u64);
			let remaining_buffer_len = block_buffer_bytes.len() - self.block_buffer_byte_len;
			if bytes.len() >= remaining_buffer_len {
				block_buffer_bytes[self.block_buffer_byte_len..].copy_from_slice(&bytes[0..remaining_buffer_len]);
				self.block_buffer_byte_len = block_buffer_bytes.len();
				bytes = &bytes[remaining_buffer_len..];
			} else {
				block_buffer_bytes[
					self.block_buffer_byte_len..(self.block_buffer_byte_len + bytes.len())
				].copy_from_slice(&bytes);
				self.block_buffer_byte_len += bytes.len();
				bytes = &[];
			}
		}
		if self.block_buffer_byte_len == block_size_bytes {
			Self::process_block(&mut self.hash_state, &block_buffer_u64);
			block_buffer_u64.fill(0);
			self.block_buffer_byte_len = 0;
		}

		// process full blocks
		while bytes.len() >= block_size_bytes {
			let block_from_bytes = &bytes[0..block_size_bytes];
			match try_cast_slice::<_, u64>(block_from_bytes) {
				Ok(bytes_as_u64) => {
					Self::process_block(&mut self.hash_state, bytes_as_u64);
				}
				Err(_) => {
					// Cast failed due to bad alignment, copy to a known good buffer that we own.
					let block_buffer_bytes = cast_slice_mut::<_, u8>(block_buffer_u64);
					block_buffer_bytes.copy_from_slice(block_from_bytes);
					Self::process_block(&mut self.hash_state, &block_buffer_u64);
					block_buffer_u64.fill(0);
				}
			}
			bytes = &bytes[block_size_bytes..];
		}

		// keep remaining bytes in buffer
		if bytes.len() > 0 {
			cast_slice_mut::<_, u8>(block_buffer_u64)[0..bytes.len()].copy_from_slice(bytes);
			self.block_buffer_byte_len = bytes.len();
		}
	}
	/// Adds a string to the hash, encoded as utf8.
	#[wasm_bindgen(js_name = updateStr)]
	pub fn update_str(&mut self, data: &str) {
		self.update(data.as_bytes());
	}
	/// Discards all the data so far
	pub fn reset(&mut self) {
		let block_size_u64 = self.bits.block_size_u64();
		self.block_buffer[0..block_size_u64].fill(0);
		self.block_buffer_byte_len = 0;
		self.hash_state.fill(0);
	}
	/// Returns the resulting hash, and resets this to the initial state.
	pub fn digest(&mut self) -> Vec<u8> {
		self.pad_and_process_block_buffer();
		let result = Vec::from(&cast_slice::<_, u8>(&self.hash_state)[0..self.bits.byte_len()]);
		self.reset();
		result
	}
	/// Returns the resulting hash as a hex-encoded string, and resets this to the initial state.
	#[wasm_bindgen(js_name = digestToHex)]
	pub fn digest_to_hex(&mut self) -> String {
		self.pad_and_process_block_buffer();
		let result = hex::encode(&cast_slice::<_, u8>(&self.hash_state)[0..self.bits.byte_len()]);
		self.reset();
		result
	}
	/// Returns the resulting hash and frees the instance. You should not use the object after calling this.
	#[wasm_bindgen(js_name = finalDigest)]
	pub fn final_digest(mut self) -> Vec<u8> {
		self.digest()
	}
	/// Returns the resulting hash and frees the instance. You should not use the object after calling this.
	#[wasm_bindgen(js_name = finalDigestToHex)]
	pub fn final_digest_to_hex(mut self) -> String {
		self.digest_to_hex()
	}


	/// Process a block, note: hash_state is expected to be of length HASH_STATE_SIZE
	fn process_block(hash_state: &mut [u64], block: &[u64]) {
		// mix data into state
		for (block_num, hash_num) in block.iter().zip(hash_state.iter_mut()) {
			// WASM uses Little-Endian. No BE to LE conversion will be done here.
			*hash_num ^= block_num;
		}
		for round in 0..KECCAK_ROUNDS {
			// Theta
			let coefficients: [u64; 5] = [
				hash_state[0] ^ hash_state[5] ^ hash_state[10] ^ hash_state[15] ^ hash_state[20],
				hash_state[1] ^ hash_state[6] ^ hash_state[11] ^ hash_state[16] ^ hash_state[21],
				hash_state[2] ^ hash_state[7] ^ hash_state[12] ^ hash_state[17] ^ hash_state[22],
				hash_state[3] ^ hash_state[8] ^ hash_state[13] ^ hash_state[18] ^ hash_state[23],
				hash_state[4] ^ hash_state[9] ^ hash_state[14] ^ hash_state[19] ^ hash_state[24]
			];
			for i in 0..5 {
				let one = coefficients[(i + 4) % 5] ^ coefficients[(i + 1) % 5].rotate_left(1);
				hash_state[i] ^= one;
				hash_state[i + 5] ^= one;
				hash_state[i + 10] ^= one;
				hash_state[i + 15] ^= one;
				hash_state[i + 20] ^= one;
			}

			// temporary
			let mut one;

			// Rho Pi
			let mut last = hash_state[1];
			one = hash_state[10]; hash_state[10] = last.rotate_left( 1); last = one;
			one = hash_state[ 7]; hash_state[ 7] = last.rotate_left( 3); last = one;
			one = hash_state[11]; hash_state[11] = last.rotate_left( 6); last = one;
			one = hash_state[17]; hash_state[17] = last.rotate_left(10); last = one;
			one = hash_state[18]; hash_state[18] = last.rotate_left(15); last = one;
			one = hash_state[ 3]; hash_state[ 3] = last.rotate_left(21); last = one;
			one = hash_state[ 5]; hash_state[ 5] = last.rotate_left(28); last = one;
			one = hash_state[16]; hash_state[16] = last.rotate_left(36); last = one;
			one = hash_state[ 8]; hash_state[ 8] = last.rotate_left(45); last = one;
			one = hash_state[21]; hash_state[21] = last.rotate_left(55); last = one;
			one = hash_state[24]; hash_state[24] = last.rotate_left( 2); last = one;
			one = hash_state[ 4]; hash_state[ 4] = last.rotate_left(14); last = one;
			one = hash_state[15]; hash_state[15] = last.rotate_left(27); last = one;
			one = hash_state[23]; hash_state[23] = last.rotate_left(41); last = one;
			one = hash_state[19]; hash_state[19] = last.rotate_left(56); last = one;
			one = hash_state[13]; hash_state[13] = last.rotate_left( 8); last = one;
			one = hash_state[12]; hash_state[12] = last.rotate_left(25); last = one;
			one = hash_state[ 2]; hash_state[ 2] = last.rotate_left(43); last = one;
			one = hash_state[20]; hash_state[20] = last.rotate_left(62); last = one;
			one = hash_state[14]; hash_state[14] = last.rotate_left(18); last = one;
			one = hash_state[22]; hash_state[22] = last.rotate_left(39); last = one;
			one = hash_state[ 9]; hash_state[ 9] = last.rotate_left(61); last = one;
			one = hash_state[ 6]; hash_state[ 6] = last.rotate_left(20); last = one;
			hash_state[1] = last.rotate_left(44);

			// Chi
			for hash_chunk in hash_state.chunks_exact_mut(5) {
				let one = hash_chunk[0];
				let two = hash_chunk[1];

				hash_chunk[0] ^= hash_chunk[2] & !two;
				hash_chunk[1] ^= hash_chunk[3] & !hash_chunk[2];
				hash_chunk[2] ^= hash_chunk[4] & !hash_chunk[3];
				hash_chunk[3] ^= one & !hash_chunk[4];
				hash_chunk[4] ^= two & !one;
			}

			// Iota
			hash_state[0] ^= XOR_MASKS[round];
		}
	}

	// process everything left in the internal buffer or add padding
	fn pad_and_process_block_buffer(&mut self) {
		let block_size_u64 = self.bits.block_size_u64();
		let block_buffer_u64 = &mut self.block_buffer[0..block_size_u64];
		let block_buffer_bytes = cast_slice_mut::<_, u8>(block_buffer_u64);

		// add a "1" byte, this is fine as the update method processes the buffer if it's full.
		block_buffer_bytes[self.block_buffer_byte_len] = 1;

		// fill rest with zeros (Unneeded as it's already zero-filled)
		// self.block_buffer_byte_len += 1;
		// block_buffer[self.block_buffer_byte_len..].fill(0);
		// and add a single set bit
		*block_buffer_bytes.last_mut().unwrap() |= 0x80;
		Self::process_block(&mut self.hash_state, &block_buffer_u64);
		// Reset state for safe dealloc or for re-use
		block_buffer_u64.fill(0);
		self.block_buffer_byte_len = 0;
	}
}

#[wasm_bindgen]
pub fn keccak224(bytes: &[u8]) -> Vec<u8> {
	let mut hasher = KeccakHash::new_with_bits(KeccakBits::Keccak224);
	hasher.update(bytes);
	hasher.final_digest()
}
#[wasm_bindgen(js_name = keccak224ToHex)]
pub fn keccak224_to_hex(bytes: &[u8]) -> String {
	let mut hasher = KeccakHash::new_with_bits(KeccakBits::Keccak224);
	hasher.update(bytes);
	hasher.final_digest_to_hex()
}

#[wasm_bindgen]
pub fn keccak256(bytes: &[u8]) -> Vec<u8> {
	let mut hasher = KeccakHash::new_with_bits(KeccakBits::Keccak256);
	hasher.update(bytes);
	hasher.final_digest()
}

#[wasm_bindgen(js_name = keccak256ToHex)]
pub fn keccak256_to_hex(bytes: &[u8]) -> String {
	let mut hasher = KeccakHash::new_with_bits(KeccakBits::Keccak256);
	hasher.update(bytes);
	hasher.final_digest_to_hex()
}

#[wasm_bindgen]
pub fn keccak384(bytes: &[u8]) -> Vec<u8> {
	let mut hasher = KeccakHash::new_with_bits(KeccakBits::Keccak384);
	hasher.update(bytes);
	hasher.final_digest()
}
#[wasm_bindgen(js_name = keccak384Hex)]
pub fn keccak384_hex(bytes: &[u8]) -> String {
	let mut hasher = KeccakHash::new_with_bits(KeccakBits::Keccak384);
	hasher.update(bytes);
	hasher.final_digest_to_hex()
}

#[wasm_bindgen]
pub fn keccak512(bytes: &[u8]) -> Vec<u8> {
	let mut hasher = KeccakHash::new_with_bits(KeccakBits::Keccak512);
	hasher.update(bytes);
	hasher.final_digest()
}
#[wasm_bindgen(js_name = keccak512Hex)]
pub fn keccak512_hex(bytes: &[u8]) -> String {
	let mut hasher = KeccakHash::new_with_bits(KeccakBits::Keccak512);
	hasher.update(bytes);
	hasher.final_digest_to_hex()
}
