/*
	This file is an almost exact copy of keccak.cpp and keccak.h by Stephan Brumme
	Modified and redistributed by Aritz Beobide-Cardinal following his "similar to the zlib license" license
	The original software can be found here: https://create.stephan-brumme.com/hash-library/
	The "similar to the zlib license" license can be found at: https://create.stephan-brumme.com/disclaimer.html
	Copyright (c) 2014,2015 Stephan Brumme
	Copyright (c) 2019 Aritz Beobide-Cardinal
*/
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#define uint8_t unsigned char
#define uint64_t unsigned long long

/// algorithm variants
enum Bits { Keccak224 = 224, Keccak256 = 256, Keccak384 = 384, Keccak512 = 512 };

/// 1600 bits, stored as 25x64 bit, BlockSize is no more than 1152 bits (Keccak224)
enum { StateSize = 1600 / (8 * 8), MaxBlockSize =  200 - 2 * (224 / 8) };

typedef struct keccak_instance {
	/// hash
	uint64_t m_hash[StateSize];
	/// size of processed data in bytes
	uint64_t m_numBytes;
	/// block size (less or equal to MaxBlockSize)
	size_t m_blockSize;
	/// valid bytes in m_buffer
	size_t m_bufferSize;
	/// bytes not processed yet
	unsigned char m_buffer[MaxBlockSize];
	/// variant
	enum Bits m_bits;
} keccak_instance;
void keccak_reset(keccak_instance* k){
	for (size_t i = 0; i < StateSize; i++){
		k->m_hash[i] = 0;
	}
	k->m_numBytes = 0;
	k->m_bufferSize = 0;
}

keccak_instance* keccak_new(enum Bits bits) {
	keccak_instance *k = malloc(sizeof(keccak_instance));
	if (k != NULL){
		k->m_blockSize = 200 - 2 * (bits / 8);
		k->m_bits = bits;
		keccak_reset(k);
	}
	return k;
}

void keccak_destroy(keccak_instance* k){
	free(k);
}

const unsigned int KeccakRounds = 24;
const uint64_t XorMasks[KeccakRounds] = {
	0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
	0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
	0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
	0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
	0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
	0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
	0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
	0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

inline uint64_t rotateLeft(uint64_t x, uint64_t numBits)   {
	return (x << numBits) | (x >> (64 - numBits));
}

unsigned int mod5(unsigned int x) 
{
	if (x < 5) {
		return x;
	}
	return x - 5;
}

void keccak_process_block(keccak_instance* k, const void* data){
	// WASM uses Little-Endian. No conversion will be done here.
	const uint64_t* data64 = (const uint64_t*) data;
	// mix data into state
	for (unsigned int i = 0; i < k->m_blockSize / 8; i++){
		k->m_hash[i] ^= data64[i];
	}
	// re-compute state
	for (unsigned int round = 0; round < KeccakRounds; round++) {
		// Theta
		uint64_t coefficients[5];
		for (unsigned int i = 0; i < 5; i++) {
			coefficients[i] = k->m_hash[i] ^ k->m_hash[i + 5] ^ k->m_hash[i + 10] ^ k->m_hash[i + 15] ^ k->m_hash[i + 20];
		}
		for (unsigned int i = 0; i < 5; i++) {
			uint64_t one = coefficients[mod5(i + 4)] ^ rotateLeft(coefficients[mod5(i + 1)], 1);
			k->m_hash[i] ^= one;
			k->m_hash[i + 5] ^= one;
			k->m_hash[i + 10] ^= one;
			k->m_hash[i + 15] ^= one;
			k->m_hash[i + 20] ^= one;
		}

		// temporary
		uint64_t one;

		// Rho Pi
		uint64_t last = k->m_hash[1];
		one = k->m_hash[10]; k->m_hash[10] = rotateLeft(last,  1); last = one;
		one = k->m_hash[ 7]; k->m_hash[ 7] = rotateLeft(last,  3); last = one;
		one = k->m_hash[11]; k->m_hash[11] = rotateLeft(last,  6); last = one;
		one = k->m_hash[17]; k->m_hash[17] = rotateLeft(last, 10); last = one;
		one = k->m_hash[18]; k->m_hash[18] = rotateLeft(last, 15); last = one;
		one = k->m_hash[ 3]; k->m_hash[ 3] = rotateLeft(last, 21); last = one;
		one = k->m_hash[ 5]; k->m_hash[ 5] = rotateLeft(last, 28); last = one;
		one = k->m_hash[16]; k->m_hash[16] = rotateLeft(last, 36); last = one;
		one = k->m_hash[ 8]; k->m_hash[ 8] = rotateLeft(last, 45); last = one;
		one = k->m_hash[21]; k->m_hash[21] = rotateLeft(last, 55); last = one;
		one = k->m_hash[24]; k->m_hash[24] = rotateLeft(last,  2); last = one;
		one = k->m_hash[ 4]; k->m_hash[ 4] = rotateLeft(last, 14); last = one;
		one = k->m_hash[15]; k->m_hash[15] = rotateLeft(last, 27); last = one;
		one = k->m_hash[23]; k->m_hash[23] = rotateLeft(last, 41); last = one;
		one = k->m_hash[19]; k->m_hash[19] = rotateLeft(last, 56); last = one;
		one = k->m_hash[13]; k->m_hash[13] = rotateLeft(last,  8); last = one;
		one = k->m_hash[12]; k->m_hash[12] = rotateLeft(last, 25); last = one;
		one = k->m_hash[ 2]; k->m_hash[ 2] = rotateLeft(last, 43); last = one;
		one = k->m_hash[20]; k->m_hash[20] = rotateLeft(last, 62); last = one;
		one = k->m_hash[14]; k->m_hash[14] = rotateLeft(last, 18); last = one;
		one = k->m_hash[22]; k->m_hash[22] = rotateLeft(last, 39); last = one;
		one = k->m_hash[ 9]; k->m_hash[ 9] = rotateLeft(last, 61); last = one;
		one = k->m_hash[ 6]; k->m_hash[ 6] = rotateLeft(last, 20); last = one;
		k->m_hash[1] = rotateLeft(last, 44);

		// Chi
		for (unsigned int j = 0; j < 25; j += 5) {
			uint64_t one = k->m_hash[j];
			uint64_t two = k->m_hash[j + 1];

			k->m_hash[j] ^= k->m_hash[j + 2] & ~two;
			k->m_hash[j + 1] ^= k->m_hash[j + 3] & ~k->m_hash[j + 2];
			k->m_hash[j + 2] ^= k->m_hash[j + 4] & ~k->m_hash[j + 3];
			k->m_hash[j + 3] ^= one & ~k->m_hash[j + 4];
			k->m_hash[j + 4] ^= two & ~one;
		}

		// Iota
		k->m_hash[0] ^= XorMasks[round];
	}
}

void keccak_update(keccak_instance* k, const void* data, size_t numBytes){
	const uint8_t* current = data;
	if (k->m_bufferSize > 0){
		while (numBytes > 0 && k->m_bufferSize < k->m_blockSize){
			k->m_buffer[k->m_bufferSize++] = *current++;
			numBytes--;
		}
	}

	// full buffer
	if (k->m_bufferSize == k->m_blockSize){
		keccak_process_block(k, &(k->m_buffer));
		k->m_numBytes += k->m_blockSize;
		k->m_bufferSize = 0;
	}
	
	// no more data ?
	if (numBytes == 0){
		return;
	}

	// process full blocks
	while (numBytes >= k->m_blockSize) {
		keccak_process_block(k, current);
		current += k->m_blockSize;
		k->m_numBytes += k->m_blockSize;
		numBytes -= k->m_blockSize;
	}

	// keep remaining bytes in buffer
	while (numBytes > 0) {
		k->m_buffer[k->m_bufferSize++] = *current++;
		numBytes--;
	}
}

// process everything left in the internal buffer
void keccak_process_buffer(keccak_instance* k){
	unsigned int blockSize = 200 - 2 * (k->m_bits / 8);   // add padding
	size_t offset = k->m_bufferSize;   // add a "1" byte
	k->m_buffer[offset++] = 1;   // fill with zeros
	while (offset < blockSize){
		k->m_buffer[offset++] = 0;
	}

	// and add a single set bit
	k->m_buffer[blockSize - 1] |= 0x80;

	keccak_process_block(k, &(k->m_buffer));
}

/// return latest hash
void keccak_final(keccak_instance* k, unsigned char *result, bool hex, bool destroy){
	keccak_process_buffer(k);
	// number of significant elements in hash (uint64_t)
	unsigned int hashLength = k->m_bits / 64;
	size_t resultLen = 0;
	for (unsigned int i = 0; i < hashLength; i++) {
		for (unsigned int j = 0; j < 8; j++) { // 64 bits => 8 bytes
      		unsigned char oneByte = (unsigned char) (k->m_hash[i] >> (8 * j));
			result[resultLen++] = oneByte; // TODO: Perhaps I could just memcpy instead?
		} 
	}

	// Keccak224's last entry in m_hash provides only 32 bits instead of 64 bits
	unsigned int remainder = k->m_bits - hashLength * 64;
	unsigned int processed = 0;
	while (processed < remainder) {
		unsigned char oneByte = (unsigned char) (k->m_hash[hashLength] >> processed);
		result[resultLen++] = oneByte;
		processed += 8;
	}
	if (hex){
		const size_t byteLen = k->m_bits / 8;
		unsigned char* rawResult = malloc(byteLen);
		if (rawResult == NULL){
			abort();
		}
		memcpy(rawResult, result, byteLen);
		resultLen = 0;
		static const char dec2hex[16 + 1] = "0123456789abcdef";
		for (size_t i = 0; i < byteLen; i++) {
    		result[resultLen++] = dec2hex[rawResult[i] >> 4];
			result[resultLen++] = dec2hex[rawResult[i] & 15];
		}
		free(rawResult);
	}
	if (destroy){
		keccak_destroy(k);
	}else{
		keccak_reset(k);
	}
}