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

import javax.crypto.IllegalBlockSizeException;

import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.midLayer.ciphertext.ByteArraySymCiphertext;
import edu.biu.scapi.midLayer.ciphertext.IVCiphertext;
import edu.biu.scapi.midLayer.ciphertext.SymmetricCiphertext;
import edu.biu.scapi.midLayer.plaintext.ByteArrayPlaintext;
import edu.biu.scapi.midLayer.plaintext.Plaintext;
import edu.biu.scapi.primitives.prf.PseudorandomPermutation;

/**
 * This class performs the randomized Counter Mode encryption and decryption.
 * By definition, this encryption scheme is CPA-secure.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class ScCTREncRandomIV extends EncWithIVAbs implements CTREnc {

	/**
	 * Default constructor. Uses default implementation of prp and SecureRandom.
	 */
	public ScCTREncRandomIV(){
		//Calls the corresponding constructor in the super class.
		super();
	}
	
	/**
	 * By passing a specific Pseudorandom permutation we are setting the type of encryption scheme.<p>
	 * This constructor gets the name of a Pseudorandom permutation and is responsible for creating a corresponding instance.<p>
	 * @param prpName the name of a specific Pseudorandom permutation, for example "AES".
	 */
	public ScCTREncRandomIV(String prpName) throws FactoriesException {
		//Calls the corresponding constructor in the super class.
		super(prpName);
	}
	
	/**
	 * By passing a specific Pseudorandom permutation we are setting the type of encryption scheme.<p>
	 * This constructor gets the name of a Pseudorandom permutation and is responsible for creating a corresponding instance.<p>
	 * It also gets the name of a Random Number Generator Algorithm to use to generate the source of randomness
	 * @param prpName the name of a specific Pseudorandom permutation, for example "AES".
	 * @param randNumGenAlg  the name of the RNG algorithm, for example "SHA1PRNG".
	 * @throws FactoriesException if the given prpName is not a valid prp name.
	 * @throws NoSuchAlgorithmException if the given randNumGenAlg is not a valid random number generator algorithm.
	 */
	public ScCTREncRandomIV(String prpName, String randNumGenAlg) throws FactoriesException, NoSuchAlgorithmException {
		//Calls the corresponding constructor in the super class.
		super(prpName, randNumGenAlg);
	}

	/**
	 * The Pseudorandom Permutation passed to the constructor of this class determines the type of encryption that will be performed.
	 * For ex: if the PRP is TripleDes, the after constructing this object we hole a CTR-TripleDes encryption scheme.
	 * @param prp the specific Pseudorandom permutation.
	 */
	public ScCTREncRandomIV(PseudorandomPermutation prp){
		//Calls the corresponding constructor in the super class.
		super(prp);
	}
	
	/**
	 * By passing a specific Pseudorandom permutation we are setting the type of encryption scheme.<p>
	 * Random object sets the source of randomness.
	 * @param prp the specific Pseudorandom permutation.
	 * @param random SecureRandom object to set the random member
	 */
	public ScCTREncRandomIV(PseudorandomPermutation prp, SecureRandom random) {
		//Calls the corresponding constructor in the super class.
		super(prp, random);
	}
	
	/** This function returns a string that is the result of concatenating "CTRwith" with the name of the underlying PRP. 
	 *  For example: "CTRwithAES"
	 */
	@Override
	public String getAlgorithmName() {
		return "CTRwith" + prp.getAlgorithmName();
	}

	/**
	 * This function performs the decryption of a ciphertext returning the corresponding decrypted plaintext.
	 * It assumes that the IV passed as part of the IVCiphertext is also the one that was used to encrypt the corresponding plaintext.
	 * @param ciphertext The Ciphertext to decrypt. Must be of type IVCiphertext.
	 * @return the decrypted plaintext.
	 * @throws IllegalArgumentException if the argument ciphertext is not specifically of type IVCiphertext.
	 * @throws IllegalStateException if no secret key was set.
	 */
	@Override
	public Plaintext decrypt(SymmetricCiphertext ciphertext){
		/* Pseudo-code:
		 *    •	ctr = ciphertext.getIV
		 *	  •	For every block in ciphertext (i = 0 to n-1) do:
		 *		o	Plaintext[i] : = ciphertext[i] XOR prp.computeBlock(ctr)
		 *		o	ctr  = ctr + 1 mod 2n
		 *	  •	Return the plaintext.
		 */
		if (!isKeySet()){
			throw new IllegalStateException("no SecretKey was set");
		}
		if (! (ciphertext instanceof IVCiphertext))
			throw new IllegalArgumentException("The ciphertext has to be of type IVCiphertext");

		//Now we know that this ciphertext is of type IVCiphertext. View it like that.
		IVCiphertext ivCipher = (IVCiphertext) ciphertext; 
		
		int cipherLengthInBytes = ivCipher.getLength();
		
		//Prepares a buffer where to store the plaintext. It has to be of the same length as the cipher.
		byte[] plaintext = new byte[cipherLengthInBytes];

		//Calculates the number of blocks in the cipher, so that we can loop over them.
		int numOfBlocksInCipher = cipherLengthInBytes / prp.getBlockSize();

		int cipherOffset = 0;
		int plaintextOffset = 0;
		int blockSize = prp.getBlockSize();
		//Views the IV passed as the counter.
		byte[] ctr = ivCipher.getIv();
		
		//First, process all full blocks. 
		//If the length of the input is not a multiple of block size, we will take care of the last part of it not here, but in the next step.
		boolean isFullBlock = true;
		for(int i = 0; i < numOfBlocksInCipher; i++){
			ctr = processBlock(ivCipher.getBytes(), cipherOffset, ctr, plaintext, plaintextOffset, isFullBlock);
			cipherOffset += blockSize; 
			plaintextOffset += blockSize;
		}
		
		
		int remainder = cipherLengthInBytes % prp.getBlockSize();
		//The last part of the cipher is of size less than blockSize.
		//Process the remaining bytes not as a full block.
		if(remainder > 0){
			isFullBlock = false;
			ctr = processBlock(ivCipher.getBytes(), cipherOffset, ctr, plaintext, plaintextOffset, isFullBlock);
		}

		return new ByteArrayPlaintext(plaintext);
	}

	/**
	 * This function performs the encryption of a plaintext returning the corresponding encrypted ciphertext.
	 * It works on plaintexts of any length.<p>
	 * It returns an object of type IVCiphertext which contains the IV used for encryption and the actual encrypted data. 
	 * @param plaintext a byte array containing the bytes to encrypt
	 * @param iv a byte array containing a (random) IV used by CTR- mode to encrypt.
	 * 
	 */
	@Override
	protected IVCiphertext encAlg(byte[] plaintext, byte[] iv) {
		/* Pseudo-code:
		 * 		•	ctr = iv
		 *		•	For each block in plaintext do: //i = 0
		 *			o	cipher[i] = prp.computeBlock(ctr) XOR plaintext[i]
		 *			o	ctr = ctr +1 mod 2n
		 */
		int plaintextLengthInBytes = plaintext.length;
		byte[] cipher = new byte[plaintextLengthInBytes];
		byte[] ctr = new byte[iv.length];
		System.arraycopy(iv,0, ctr, 0, iv.length);

		int numOfBlocksInPlaintext = plaintextLengthInBytes / prp.getBlockSize();

		int cipherOffset = 0;
		int plaintextOffset = 0;
		int blockSize = prp.getBlockSize();

		//For each block in ciphertext do:
		boolean isFullBlock = true;
		for(int i = 0; i < numOfBlocksInPlaintext; i++){
			ctr = processBlock(plaintext, plaintextOffset, ctr, cipher, cipherOffset, isFullBlock);
			cipherOffset += blockSize; 
			plaintextOffset += blockSize;
		}
		int remainder = plaintextLengthInBytes % prp.getBlockSize();
		//The last part of the plaintext is of size less than blockSize.
		//Process the remaining bytes not as a full block.
		if(remainder > 0){
			isFullBlock = false;
			ctr = processBlock(plaintext, plaintextOffset, ctr, cipher, cipherOffset, isFullBlock);
		}

		return new IVCiphertext(new ByteArraySymCiphertext(cipher), iv);
	}


	/* This function processes a single block. It can be called both by encrypt and by decrypt.<p>
	 * If called by encrypt then the first two arguments refer to the plaintext being processed and the resulting cipher is written to "out".<p>
	 * If called by decrypt then the first two arguments refer to the cipher being processed and the resulting plaintext is written to "out". <p>
	 * The data is not required to be aligned to the block size of this instance of the encryption scheme. If it is not, then the last part of the data needs special care.
	 * Pseudo-code:
	 * 		•out[i] = prp.computeBlock(ctr) XOR in[i]
	 *		•ctr = ctr +1 mod 2n
	 * 
	 * @param in a byte array containing the data to be processed
	 * @param inOffset the offset in "in" byte array
	 * @param ctr the counter used by the counter mode of operation
	 * @param out a byte array containing the processed data
	 * @param outOffset the offset in "out" byte array
	 * @param isFullBlock a boolean indicating if the data is aligned to the block size of this instance of the encryption scheme, or not. 
	 * 
	 * @return the incremented counter
	 * 
	 */
	private byte[] processBlock(byte[] in, int inOffset, byte[] ctr, byte[] out, int outOffset, boolean isFullBlock){
		int blockSize = prp.getBlockSize();
		//Here we have to create a new array because we can't override in and ctr arrays and out array may not be long enough.
		byte[] prpBytes = new byte[blockSize]; 
		try {
			prp.computeBlock(ctr, 0, blockSize, prpBytes, 0, blockSize);
		} catch (IllegalBlockSizeException e) {
			//We catch this exception here because there is no chance that the ctr will have the wrong the size.
			e.printStackTrace();
		} 

		if(isFullBlock) {
			for(int i = 0 ; i < blockSize; i++){
				out[outOffset + i] = (byte)(in[inOffset + i] ^ prpBytes[i]); 
			}
		}else{
			//Only XOR the relevant bytes.
			int partialBlockLength = in.length - inOffset;
			for(int i = 0 ; i < partialBlockLength; i++){
				out[outOffset + i] = (byte)(in[inOffset + i] ^ prpBytes[i]); 
			}
		}

		//Increases the counter by one.
		int    carry = 1;

		for (int i = blockSize - 1; i >= 0; i--)
		{
			int    x = (ctr[i] & 0xff) + carry;

			if (x > 0xff)
			{
				carry = 1;
			}
			else
			{
				carry = 0;
			}

			ctr[i] = (byte)x;
		}
		return ctr;

	}

}
