/**
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
* Copyright (c) 2012 - SCAPI (http://crypto.biu.ac.il/scapi)
* This file is part of the SCAPI project.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
* 
* Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"),
* to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
* and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
* 
* The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
* 
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
* FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
* WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
* 
* We request that any publication and/or code referring to and/or based on SCAPI contain an appropriate citation to SCAPI, including a reference to
* http://crypto.biu.ac.il/SCAPI.
* 
* SCAPI uses Crypto++, Miracl, NTL and Bouncy Castle. Please see these projects for any further licensing issues.
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
*/


package edu.biu.scapi.midLayer.symmetricCrypto.encryption;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.logging.Level;

import javax.crypto.IllegalBlockSizeException;

import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.generals.Logging;
import edu.biu.scapi.midLayer.ciphertext.ByteArraySymCiphertext;
import edu.biu.scapi.midLayer.ciphertext.IVCiphertext;
import edu.biu.scapi.midLayer.ciphertext.SymmetricCiphertext;
import edu.biu.scapi.midLayer.plaintext.ByteArrayPlaintext;
import edu.biu.scapi.midLayer.plaintext.Plaintext;
import edu.biu.scapi.paddings.BitPadding;
import edu.biu.scapi.paddings.NoPadding;
import edu.biu.scapi.paddings.PaddingScheme;
import edu.biu.scapi.primitives.prf.PseudorandomPermutation;
import edu.biu.scapi.tools.Factories.PaddingFactory;

/**
 * This class performs the Cipher Block Chaining (CBC) Mode encryption and decryption.
 * By definition, this encryption scheme is CPA-secure.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class ScCBCEncRandomIV extends EncWithIVAbs implements CBCEnc {

	private PaddingScheme padding; //Padding scheme to use if the message for encryption needs a pad.
	
	
	/**
	 * Default constructor. Uses default implementation of prp, SecureRandom and padding.
	 */
	public ScCBCEncRandomIV(){
		super();
		//Sets the padding member to a bitPadding.
		setPadding(new BitPadding());
	}
	
	private void setPadding(PaddingScheme padding){
		this.padding = padding;
	}
	
	/**
	 * Sets the underlying prp that determines the type of encryption that will be performed, and the padding scheme to use.
	 * A default source of randomness is used.
	 * @param prp the underlying pseudorandom permutation.
	 * @param padding the padding scheme to use.
	 */
	public ScCBCEncRandomIV(PseudorandomPermutation prp, PaddingScheme padding) {
		super(prp);
		//Sets the padding member.
		setPadding(padding);
	}
	
	/**
	 * Sets the underlying prp that determines the type of encryption that will be performed, and the padding scheme to use.
	 * The random passed to this constructor determines the source of randomness that will be used.
	 * @param prp the underlying pseudorandom permutation.
	 * @param random a user provided source of randomness.
	 * @param padding the padding scheme to use.
	 */
	public ScCBCEncRandomIV(PseudorandomPermutation prp, SecureRandom random, PaddingScheme padding) {
		super(prp, random);
		//Sets the padding member.
		setPadding(padding);
	}
	
	
	/**
	 * By passing a specific Pseudorandom permutation we are setting the type of encryption scheme.<p>
	 * This constructor gets the name of a Pseudorandom permutation and is responsible for creating a corresponding instance.<p>
	 * It also gets the name of a Random Number Generator Algorithm to use to generate the source of randomness<p> and the name of a Padding Scheme. 
	 * @param prpName the name of a specific Pseudorandom permutation, for example "AES".
	 * @param paddingName name of the Padding Scheme to use, for example "BitPadding".
	 * @param randNumGenAlg  the name of the RNG algorithm, for example "SHA1PRNG"
	 * @throws FactoriesException if the given names are not valid prp name or padding name.
	 * @throws NoSuchAlgorithmException  if the given randNumGenAlg is not a valid random number generator.
	 */
	public ScCBCEncRandomIV(String prpName, String paddingName, String randNumGenAlg) throws FactoriesException, NoSuchAlgorithmException {
		super(prpName, randNumGenAlg);
		//Sets the padding member.
		setPadding(PaddingFactory.getInstance().getObject(paddingName)); 
	}

	/**
	 * By passing a specific Pseudorandom permutation we are setting the type of encryption scheme.<p>
	 * This constructor gets the name of a Pseudorandom permutation and is responsible for creating a corresponding instance.<p>
	 * It also gets the name of a Padding Scheme. 
	 * A defualt source of randomness is used.
	 * @param prpName the name of a specific Pseudorandom permutation, for example "AES".
	 * @param paddingName name of the Padding Scheme to use, for example "BitPadding".
	 * @throws FactoriesException if the given names are not valid prp name or padding name.
	 */
	public ScCBCEncRandomIV(String prpName, String paddingName) throws FactoriesException {
		super(prpName);
		//Sets the padding member.
		setPadding(PaddingFactory.getInstance().getObject(paddingName)); 
	}
	
	/**
	 * @return the algorithm name - CBC and the underlying prp name
	 */
	@Override
	public String getAlgorithmName() {
		return "CBCwith" + prp.getAlgorithmName();
		
	}

	/**
	 * Decrypts the given ciphertext using the CBC mode of operation and the underlying prp as the block cipher function.
	 * 
	 * @param ciphertext the given ciphertext to decrypt. MUST be an instance of IVCiphertext.
	 * @return the plaintext object containing the decrypted ciphertext.
	 * @throws IllegalStateException if no secret key was set.
	 * @throws IllegalArgumentException if the given ciphertext is not an instance of IVCiphertext.
	 */
	@Override
	public Plaintext decrypt(SymmetricCiphertext ciphertext) {
		/* The algorithm pseudo-code is: 
		 * 		•	plaintext[0] = prp.invert(cipher[0]) XOR IV
		 *		•	For i from 1 to length of plaintext do:
		 *			o	plaintext[i] : = prp.invert(cipher[i]) XOR ciphertext[i-1]
		 */
		if (!isKeySet()){
			throw new IllegalStateException("no SecretKey was set");
		}
		//If the ciphertext is not of type IVCiphertext - throws exception.
		if (!(ciphertext instanceof IVCiphertext)){
			throw new IllegalArgumentException("The ciphertext has to be of type IVCiphertext");
		}
		//Gets the iv and the ciphertext bytes from the IVCiphertext parameters.
		byte[] iv = ((IVCiphertext) ciphertext).getIv();
		byte[] cipher = ciphertext.getBytes();
		
		//Prepares a buffer where to store the plaintext, of the same length as the cipher.
		byte[] paddedPlaintext = new byte[cipher.length];
		
		int blockSize = prp.getBlockSize();
		//Number of whole blocks.
		int numberBlocksInCipher = cipher.length / blockSize;
		
		
		//Process the first block plaintext[0] = prp.invertBlock(cipher[0])^IV.
		decryptBlock(cipher, 0, iv, 0, paddedPlaintext, 0);
		
		//Process the other blocks of the cipher. plaintext[i] : = prp.invert(cipher[i]) XOR ciphertext[i-1] .
		int i;
		for (i=1; i<numberBlocksInCipher; i++){
			decryptBlock(cipher, i*blockSize, cipher, (i-1)*blockSize, paddedPlaintext, i*blockSize);
		}
		
		//Removes pad.
		byte[] plaintext = padding.removePad(paddedPlaintext);
		
		//Returns the result plaintext.
		return new ByteArrayPlaintext(plaintext);
	}
	
	/**
	 * Processes the given block.
	 * This function inverts the cipher using the prp.invertBlock function and 'xores' the result with the iv to get the plaintext.
	 * @param in ciphertext block.
	 * @param inOff offset within the ciphertext to take the bytes from.
	 * @param iv the bytes to be xored with the inverted cipher block (it can be the IV or a ciphertext block).
	 * @param ivOff offset within the iv to take the bytes from.
	 * @param out plaintext block to put the result in.
	 * @param outOff offset within the plaintext to put the bytes from.
	 */
	private void decryptBlock(byte[] in, int inOff, byte[] iv, int ivOff, byte[] out, int outOff){
		int size = prp.getBlockSize();
		
		try {
			//inverts the block. Puts the result in the given out array. 
			//TODO check that putting the result in the output array doesn't causes security problems.
			prp.invertBlock(in, inOff, out, outOff, size);
		
			//Xores the result bytes with the iv.
			for(int i=0; i<size; i++){
				out[outOff + i] = (byte) (iv[ivOff + i] ^ out[outOff + i]);
			}
		} catch (IllegalBlockSizeException e) {
			// Shouldn't occur since the arrays are of block size.
			Logging.getLogger().log(Level.WARNING, e.toString());
		} 
		
	}

	/**
	 * Encrypts the given plaintext using the CBC mode of operation and the underlying prp as the block cipher function.
	 * The given plaintext can be at any length.
	 * 
	 * @param plaintext the given plaintext to encrypt.
	 * @param iv random bytes used in the CBC mode of operation.
	 * @return the ciphertext object containing the encrypted plaintext.
	 */
	@Override
	protected IVCiphertext encAlg(byte[] plaintext, byte[] iv) {
		/* The algorithm pseudo-code is: 
		 * 		•	ciphertext[0] = prp.computeBlock(iv XOR plaintext[0])
		 *		•	for next blocks in plaintext do: //i = 1
		 *			o	ciphertext [i] = prp.computeBlock(ciphertext [i-1] XOR plaintext[i])
		 */
		byte[] paddedPlaintext; // Will contain the padded plaintext.
		
		int blockSize = prp.getBlockSize();
		
		// If padding is not "NoPadding", pads the plaintext.
		if (!(padding instanceof NoPadding)){
			int numBytesToPad = numBytesToPad(plaintext); //Calculates the number of bytes to pad.
			paddedPlaintext = padding.pad(plaintext, numBytesToPad);
		} else {
			//If padding is "NoPadding" and the plaintext is not aligned, throws exception.
			if ((plaintext.length % blockSize) != 0){
				throw new IllegalArgumentException("plaintext is not aligned to blockSize");
			}
			//If the plaintext is aligned, puts it as the padded plaintext.
			paddedPlaintext = plaintext;
		}
		
		//Prepares the ciphertext array of size equals to the plaintext.
		byte[] cipher = new byte[paddedPlaintext.length];
		
		//Number of whole blocks.
		int numberBlocksInCipher = paddedPlaintext.length / blockSize;
		
		//Process the first block cipher[0] = prp.computeBlock(plaintext[0]^iv).
		encryptBlock(paddedPlaintext, 0, iv, 0, cipher, 0);
		
		//Process the other blocks of the plaintext. ciphertext [i] = prp.computeBlock(ciphertext [i-1] XOR plaintext[i]).
		int i;
		for (i=1; i<numberBlocksInCipher; i++){
			encryptBlock(paddedPlaintext, i*blockSize, cipher, (i-1)*blockSize, cipher, i*blockSize);
		}
		
		//Returns an IVCiphertext with the cipher and the IV.
		return new IVCiphertext(new ByteArraySymCiphertext(cipher), iv);
	}
	
	/**
	 * Processes the given block.
	 * This function 'xores' the input with the iv, sends it to the prp.computeBlock and put the result in the output array.
	 * @param in plaintext block.
	 * @param inOff offset within the plaintext to take the bytes from.
	 * @param iv the bytes to be xored with the plaintext bytes (it can be the IV or a cipher block).
	 * @param ivOff offset within the iv to take the bytes from.
	 * @param out ciphertext block to put the result in.
	 * @param outOff offset within the ciphertext to put the bytes from.
	 */
	private void encryptBlock(byte[] in, int inOff, byte[] iv, int ivOff, byte[] out, int outOff){
		int size = prp.getBlockSize();
		
		//Xores the inbytes with the iv. Puts the result in the given out array.
		for(int i=0; i<size; i++){
			out[outOff + i] = (byte) (iv[ivOff + i] ^ in[inOff + i]);
		}
		//Computes the prp computeBlock function on the xored bytes. 
		//Puts the result in the out array.
		try {
			prp.computeBlock(out, outOff, size, out, outOff);
		} catch (IllegalBlockSizeException e) {
			// Shouldn't occur since the arrays are of block size.
			Logging.getLogger().log(Level.WARNING, e.toString());
		} 
	}

	/**
	 * Calculates the number of bytes to pad.
	 * If the input is aligned to block size, returns block size.
	 * else, return the number of bytes to add in order to align the input to a block size.
	 * @param input array that need padding.
	 * @return number of bytes to pad.
	 */
	private int numBytesToPad(byte[] input){
		int len = input.length;
		int BlockSize = prp.getBlockSize();
		int bytesInLastBlock = len % BlockSize;
		//If the array is aligned, returns block size.
		if (bytesInLastBlock == 0){
			return BlockSize;
		//If the array is not aligned, returns the number of bytes to add in order to be aligned.
		} else {
			return BlockSize - bytesInLastBlock;
		}
	}
}
