package quinn.deschat.encryption;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.SecureRandom;

/**
 * 
 * @author Brandon Quinn
 *
 * Implementation mostly according to FIPS 46-3 
 * https://csrc.nist.gov/files/pubs/fips/46-3/final/docs/fips46-3.pdf
 * 
 * Other references
 * https://en.wikipedia.org/wiki/DES_supplementary_material
 * https://page.math.tu-berlin.de/~kant/teaching/hess/krypto-ws2006/des.htm
 * 
 */
public class DES {
	
	/**
	 * Size of key.
	 */
	public static final int KEY_SIZE_BYTES = 8; // 64-bit
	
	/**
	 * Key, stored as it changes through the key generation method for each round
	 */
	private byte[] keyn;
	
	// Initial permutation, applies to the initial 64-bit sized block
	int[][] IP = {
			{58, 50, 42, 34, 26, 18, 10, 2},
			{60, 52, 44, 36, 28, 20, 12, 4},
			{62, 54, 46, 38, 30, 22, 14, 6},
			{64, 56, 48, 40, 32, 24, 16, 8},
			{57, 49, 41, 33, 25, 17, 9, 1},
			{59, 51, 43, 35, 27, 19, 11, 3},
			{61, 53, 45, 57, 29, 21, 13, 9},
			{63, 55, 47, 39, 31, 23, 15, 7}
	};
	
	// Inverse of the first permutation applied to the preoutput
	int[][] IPInverse = {
			{40, 8, 48, 16, 56, 24, 64, 32},
			{39, 7, 47, 15, 55, 23, 63, 31},
			{38, 6, 46, 14, 54, 22, 62, 30},
			{37, 5, 45, 13, 53, 21, 61, 29},
			{36, 4, 44, 12, 52, 20, 60, 28},
			{35, 3, 43, 11, 51, 19, 59, 27},
			{34, 2, 42, 10, 50, 18, 58, 26},
			{33, 1, 41, 9, 49, 17, 57, 25}
	};
	
	// Expansion table
	int[][] eTable = {
			{2, 1, 2, 3, 4, 5},
			{4, 5, 6, 7, 8, 9}, 
			{8, 9, 10, 11, 12, 13}, 
			{12, 13, 14, 15, 16, 17}, 
			{16, 17, 18, 19, 20, 21}, 
			{20, 21, 22, 23, 24, 25}, 
			{24, 25, 26, 27, 28, 29}, 
			{28, 29, 30, 31, 32, 1}
	};
	
	// P-Table
	int[][] permutationTable = {
			{16, 7, 20, 21},
			{29, 12, 28, 17},
			{1, 15, 23, 26},
			{5, 18, 31, 10},
			{2, 8, 24, 14},
			{32, 27, 3, 9},
			{19, 13, 30, 6},
			{22, 11, 4, 25}
	};
	
	// Substitution Boxes
	
	int[][] S1 = {
		{14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
		{0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8}, 
		{4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0}, 
		{15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}
	};
	
	int[][] S2 = { 
		{15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10}, 
		{3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5}, 
		{0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15}, 
		{13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}
	};
	
	int[][] S3 = {
		{10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8}, 
		{13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1}, 
		{13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7}, 
		{1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}
	};
	
	int[][] S4 = {
		{7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
		{13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
		{10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
		{3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}
	};
	 
	int[][] S5 = {
		{2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
		{14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
		{4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
		{11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}
	};
	
	int[][] S6 = {
		{12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
		{10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
		{9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
		{4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}
	};
	
	int[][] S7 = {
		{4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
		{13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6}, 
		{1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2}, 
		{6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12} 
	};
	
	int[][] S8 = {
		{13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7}, 
		{1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2}, 
		{7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8}, 
		{2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}
	};
	
	// Permuted Choice One (PC-1)
	int[][] PC1 = {
			{57, 49, 41, 33, 25, 17, 9},
			{1, 58, 50, 42, 34, 26, 18},
			{10, 2, 59, 51, 43, 35, 27},
			{19, 11, 3, 60, 52, 44, 36},
			{63, 55, 47, 39, 31, 23, 15},
			{7, 62, 54, 46, 38, 30, 22},
			{14, 6, 61, 53, 45, 37, 29},
			{21, 13, 5, 28, 20, 12, 4}
	};
	
	// Permuted Choice Two (PC-2)
	int[][] PC2 = {
			{14, 17, 11, 24, 1, 5, 3, 28},
			{15, 6, 21, 10, 23, 19, 12, 4},
			{26, 8, 16, 7, 27, 20, 13, 2},
			{41, 52, 31, 37, 47, 55, 30, 40},
			{51, 45, 33, 48, 44, 49, 39, 56},
			{34, 53, 46, 42, 50, 36, 29, 32}
	};
	
	/**
	 * Encrypt the plaintext of arbitrary length (TODO: Implement padding and CBC).
	 * 
	 * @param plaintext
	 * @param key
	 * @return
	 */
	public byte[] encrypt(final String plaintext, final byte[] key) {
		assert (key.length == KEY_SIZE_BYTES);
		
		keyn = key;
		
		// divide the plaintext in to blocks of 64 bits (byte array, 8 long)
		// TODO: Add padding for plaintext that isn't long enough
		byte[][] blocks = dividePlaintext(plaintext);
		byte[][] encryptedBlocks = new byte[blocks.length][8];
		
		// go through each block and encrypt them
		for (int i = 0; i < blocks.length; i++) {
			encryptedBlocks[i] = encryptBlock(blocks[i]);
		}
		
		return null;
	}
	
	/**
	 * The actual encryption method which encrypts a single 64bit blocks and
	 * returns the 64bit. 
	 * 
	 * @param block
	 * @return
	 */
	private byte[] encryptBlock(final byte[] block) {
		byte[] encryptedBlock;
		
		encryptedBlock = permutation(block, IP);
		
		for (int r = 0; r < 16; r++) {
			encryptedBlock = round(encryptedBlock);
		}
		
		// final permutation
		encryptedBlock = permutation(encryptedBlock, IPInverse);
		
		return encryptedBlock;
	}
	
	/**
	 * The main function for a single round of the feistel structure.
	 * 
	 * @param block
	 * @return
	 */
	private byte[] round(final byte[] block) {
		// split the block in to 2 32bit blocks (L and R)
		byte[] L = leftHalfOf64BitBlock(block);
		byte[] R = rightHalfOf64BitBlock(block);
		byte[] newR;
		
		// send R in to f and kn into f
		newR = XOR32bit(L, f(R, keyGen(keyn)));
		
		// XOR L and result of f
		return join32bitBlocks(R, newR);
	}
	
	/**
	 * Simply combines 2 byte arrays of 4 bytes long and combines
	 * them in to 1 8 byte array.
	 * 
	 * @param L left
	 * @param R right
	 * @return 8 byte long array
	 */
	private byte[] join32bitBlocks(byte[] L, byte[] R) {
		assert (L.length == 4 && R.length == 4);

		byte[] result = new byte[8];
		result[0] = L[0];
		result[1] = L[1];
		result[2] = L[2];
		result[3] = L[3];

		result[4] = L[0];
		result[5] = L[1];
		result[6] = L[2];
		result[7] = L[3];

		return result;
	}

	/**
	 * Exclusive OR of the Left and Right half of the input to the feistel structure.
	 * 
	 * @param L
	 * @param R
	 * @return
	 */
	private byte[] XOR32bit(final byte[] L, final byte[] R) {
		assert (L.length == 4 && R.length == 4);
		
		byte[] result = new byte[L.length];
		
		result[0] = (byte) (L[0] ^ R[0]);
		result[1] = (byte) (L[1] ^ R[1]);
		result[2] = (byte) (L[2] ^ R[2]);
		result[3] = (byte) (L[3] ^ R[3]);
		
		return result;
	}
	
	/**
	 * f function in each round that takes in the key and applies the substitution 
	 * boxes.
	 * 
	 * @param rBlock
	 * @param kn
	 * @return
	 */
	private byte[] f(final byte[] rBlock, final byte[] kn) {
		assert (rBlock.length == 4 && kn.length == 8);
		
		return null;
	}
	
	/**
	 * Generates the new key for each round.
	 * 
	 * @param keyn
	 * @return
	 */
	private byte[] keyGen(final byte[] keyn) {
		
		return null;
	}
	
	/**
	 * Takes in a 64-bit (8 byte) long array and removes every 8th bit
	 * returning a 56-bit (7 byte) long array.
	 * 
	 * @param key
	 * @return
	 */
	private byte[] parityBitDrop(final byte[] key) {
		assert (key.length == 0 && key != null);

		int currentBitOfCurrentByte = 4;
		int resultByteIndex = 0;
		int resultByteBitIndex = 0;
		byte[] result = new byte[7];

		for (int i = 0; i < key.length; i++) {
			// move from left to right of each byte, check if 
			// each bit is a 1 or a 0 and move it in to the new byte array
			// skip the 8th bit of each byte (where currentBitOfCurrentByte == 0)
			byte currentByte = key[i];
			
			
		}

		return result;
	}

	private byte[] leftHalfOf64BitBlock(byte[] block) {
		assert (block.length == 8);
		
		byte[] result = new byte [block.length >> 1];
		
		result[0] = block[0];
		result[1] = block[1];
		result[2] = block[2];
		result[3] = block[3];
		
		return result;
	}
	
	private byte[] rightHalfOf64BitBlock(byte[] block) {
		assert (block.length == 8);
		
		byte[] result = new byte [block.length/2];
		
		result[0] = block[4];
		result[1] = block[5];
		result[2] = block[6];
		result[3] = block[7];
		
		return result;
	}
	
	/**
	 * Expand the 32bit input to 48bits using the expansion table
	 */
	private byte[] expansion32bitsTo48bits(final byte[] block) {
		// the permutation method will expand as well,
		// just need to truncate the first 16 bits because they're not used,
		// permutation returns 64 bits
		byte[] perm = permutation(block, eTable);
		byte[] expandedBlock = new byte[6];
		for (int i = 0; i < 6; i++) {
			expandedBlock[i] = perm[i+2];
		}
		
		return expandedBlock;
	}
	
	/**
	 * 
	 * 
	 * @param block
	 * @return
	 */
	private byte[] permutation(final byte[] block, final int[][] permutation) {
		long result = 0;

		// convert the block in to a long
		long blockToWorkOn = new BigInteger(block).longValue();
		
		// go through each element in the permutation table
		int bitToCopy = 0;
		int setBit = block.length;
		for (int x = 0, y = 0; x < permutation[0].length && y < permutation.length;) {
			bitToCopy = permutation[y][x];
			
			// shift right to move the bit we want to copy to the end
			long bitToCopyAtLSB = blockToWorkOn >> bitToCopy;
		
			// check if the last bit is a 1 by doing an & operation with 1
			long bitToApply = bitToCopyAtLSB & 1;
			
			// move the bit to the location it needs to be in the result, and or it
			// with the result
			bitToApply = bitToApply << setBit;
			result = result | bitToApply;
			
			setBit --;
			x++;
			if (x == permutation[0].length) {x = 0; y++;};
			if (y == permutation.length && x == permutation[0].length) break;
		}
		
		// convert the resulting long in to a byte array
		ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
		buffer.putLong(result);
		return buffer.array();
	}
	
	/**
	 * Break the plaintext down in to blocks of 64 bits.
	 * @return
	 */
	byte[][] dividePlaintext(final String plaintext) {
		int numBlocks = plaintext.length() / 8;
		if (numBlocks < 1) numBlocks = 1;
		
		byte[][] blocksInBytes = new byte[numBlocks][8];
		
		int s = 0;
		for (int b = 0; b < numBlocks; b++) {
			for (int i = 0; i < 8; i++) {
				blocksInBytes[b][i] = (byte)(plaintext.charAt(s));
				s++;
				if (s == plaintext.length()) break;
			}
		}
		
		return blocksInBytes;
	}
	
	/**
	 * Randomly generate a 56-bit byte array, that is 7 random bytes.
	 * @return
	 */
	public byte[] generateKey() {
		SecureRandom random = new SecureRandom(); 
		random.reseed();
		byte[] K = new byte[KEY_SIZE_BYTES];
		random.nextBytes(K);
		return K;
	}
}
