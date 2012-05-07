package edu.biu.scapi.midLayer.symmetricCrypto.encryption;


import java.math.BigInteger;

import javax.crypto.IllegalBlockSizeException;

import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.midLayer.ciphertext.BasicSymCiphertext;
import edu.biu.scapi.midLayer.ciphertext.Ciphertext;
import edu.biu.scapi.midLayer.ciphertext.IVCiphertext;
import edu.biu.scapi.midLayer.plaintext.BasicPlaintext;
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
	 * By passing a specific Pseudorandom permutation we are setting the type of encryption scheme.<p>
	 * This constructor gets the name of a Pseudorandom permutation and is responsible for creating a corresponding instance.<p>
	 * The init function must be called subsequently in order to work properly with this encryption object.
	 * @param prp the name of a specific Pseudorandom permutation, for example "AES".
	 */
	public ScCTREncRandomIV(String prpName) throws FactoriesException {
		super(prpName);
	}

	/**
	 * The Pseudorandom Permutation passed to the constructor of this class determines the type of encryption that will be performed.
	 * For ex: if the PRP is TripleDes, the after constructing this object we hole a CTR-TripleDes encryption scheme.
	 * @param prp
	 */
	public ScCTREncRandomIV(PseudorandomPermutation prp){
		super(prp);
	}
	
	/** This function returns a string that is the result of concatenating "CTRwith" with the name of the underlying PRP. 
	 *  For example: "CTRwithAES"
	 * @see edu.biu.scapi.midLayer.symmetricCrypto.encryption.SymmetricEnc#getAlgorithmName()
	 */
	@Override
	public String getAlgorithmName() {
		return "CTRwith" + prp.getAlgorithmName();
	}

	/**This function performs the decryption of a ciphertext returning the corresponding decrypted plaintext.
	 * It requires the ciphertext to be of type IVCiphertext, if not, an IllegalArgumentException is thrown.<p>
	 * It assumes that the IV passed as part of the IVCiphertext is also the one that was used to encrypt the corresponding plaintext.
	 * Pseudo-code:
	 *    •	ctr = ciphertext.getIV
	 *	  •	For every block in ciphertext (i = 0 to n-1) do:
	 *		o	Plaintext[i] : = ciphertext[i] XOR prp.computeBlock(ctr)
	 *		o	ctr  = ctr + 1 mod 2n
	 *	  •	Return the plaintext.
	 *
	 * @see edu.biu.scapi.midLayer.symmetricCrypto.encryption.SymmetricEnc#decrypt(edu.biu.scapi.midLayer.ciphertext.Ciphertext)
	 * 
	 * @param ciphertext The Ciphertext to decrypt
	 * @return the decrypted plaintext
	 * @throws IllegalArgumentException if the argument ciphertext is not specifically of type IVCiphertext
	 */
	@Override
	public Plaintext decrypt(Ciphertext ciphertext){
		if (! (ciphertext instanceof IVCiphertext))
			throw new IllegalArgumentException("The ciphertext has to be of type IVCiphertext");

		//Now we know that this ciphertext is of type IVCiphertext. View it like that.
		IVCiphertext ivCipher = (IVCiphertext) ciphertext; 
		
		int cipherLengthInBytes = ivCipher.getLength();
		
		//Prepare a buffer where to store the plaintext. It has to be of the same length as the cipher.
		byte[] plaintext = new byte[cipherLengthInBytes];

		//Calculate the number of blocks in the cipher, so that we can loop over them.
		int numOfBlocksInCipher = cipherLengthInBytes / prp.getBlockSize();

		int cipherOffset = 0;
		int plaintextOffset = 0;
		int blockSize = prp.getBlockSize();
		//View the IV passed as the counter.
		byte[] ctr = ivCipher.getIv();
		
		System.out.println("In decrypt, the iv = " + new BigInteger(ctr));
		for(int i = 0; i < 16; i++){
			System.out.print(ctr[i] + " ");
		}
		
		//First, process all full blocks. 
		//If the length of the input is not a multiple of block size, we will take care of the last part of it not here, but in the next step
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

		return new BasicPlaintext(plaintext);
	}

	/**This function performs the encryption of a plaintext returning the corresponding encrypted ciphertext.
	 * It works on plaintexts of any length.<p>
	 * It returns an object of type IVCiphertext which contains the IV used for encryption and the actual encrypted data. 
	 * Pseudo-code:
	 * 		•	ctr = iv
	 *		•	For each block in plaintext do: //i = 0
	 *			o	cipher[i] = prp.computeBlock(ctr) XOR plaintext[i]
	 *			o	ctr = ctr +1 mod 2n
	 *
	 * @see edu.biu.scapi.midLayer.symmetricCrypto.encryption.EncWithIVAbs#encAlg(byte[], byte[])
	 * 
	 * @param plaintext a byte array containing the bytes to encrypt
	 * @param iv 		a byte array containing a (random) IV used by CTR- mode to encrypt.
	 * 
	 */
	@Override
	protected IVCiphertext encAlg(byte[] plaintext, byte[] iv) {
		
		int plaintextLengthInBytes = plaintext.length;
		byte[] cipher = new byte[plaintextLengthInBytes];
		byte[] ctr = new byte[iv.length];
		System.arraycopy(iv,0, ctr, 0, iv.length);

		//System.out.println("In encrypt, the iv = " + new BigInteger(ctr));

		
		int numOfBlocksInPlaintext = plaintextLengthInBytes / prp.getBlockSize();

		int cipherOffset = 0;
		int plaintextOffset = 0;
		int blockSize = prp.getBlockSize();

		//for each block in ciphertext do:
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

		return new IVCiphertext(new BasicSymCiphertext(cipher), iv);
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


		//increase the counter by one.
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
