package edu.biu.scapi.midLayer.symmetricCrypto.encryption;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.logging.Level;

import javax.crypto.IllegalBlockSizeException;

import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.generals.Logging;
import edu.biu.scapi.midLayer.ciphertext.BasicSymCiphertext;
import edu.biu.scapi.midLayer.ciphertext.Ciphertext;
import edu.biu.scapi.midLayer.ciphertext.IVCiphertext;
import edu.biu.scapi.midLayer.ciphertext.SymmetricCiphertext;
import edu.biu.scapi.midLayer.plaintext.BasicPlaintext;
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

	private PaddingScheme padding;
	
	
	/**
	 * Default constructor
	 */
	public ScCBCEncRandomIV(){
		super();
		this.padding = new BitPadding();
	}
	
	/**
	 * Sets the underlying prp that determines the type of encryption that will be performed.
	 * A default source of randomness is used.
	 * @param prp the underlying pseudorandom permutation
	 * @param padding the padding scheme to use
	 * @throws FactoriesException if the creation of the padding scheme failed
	 */
	public ScCBCEncRandomIV(PseudorandomPermutation prp, PaddingScheme padding) {
		super(prp);
		this.padding = padding;
	}
	
	/**
	 * Sets the underlying prp that determines the type of encryption that will be performed.
	 * The random passed to this constructor determines the source of randomness that will be used.
	 * @param prp the underlying pseudorandom permutation
	 * @param random a user provided source of randomness
	 * @param padding the padding scheme to use
	 */
	public ScCBCEncRandomIV(PseudorandomPermutation prp, SecureRandom random, PaddingScheme padding) {
		super(prp, random);
		this.padding = padding;
	}
	
	
	/**
	 * By passing a specific Pseudorandom permutation we are setting the type of encryption scheme.<p>
	 * This constructor gets the name of a Pseudorandom permutation and is responsible for creating a corresponding instance.<p>
	 * It also gets the name of a Random Number Generator Algorithm to use to generate the source of randomness<p> and the name of a Padding Scheme. 
	 * @param prp the name of a specific Pseudorandom permutation, for example "AES".
	 * @param randNumGenAlg  the name of the RNG algorithm, for example "SHA1PRNG"
	 * @param paddingName name of the Padding Scheme to use
	 * @throws FactoriesException 
	 * @throws NoSuchAlgorithmException 
	 */
	public ScCBCEncRandomIV(String prpName, String paddingName, String randNumGenAlg) throws FactoriesException, NoSuchAlgorithmException {
		super(prpName, randNumGenAlg);
		this.padding = PaddingFactory.getInstance().getObject(paddingName);
	}

	/**
	 * By passing a specific Pseudorandom permutation we are setting the type of encryption scheme.<p>
	 * This constructor gets the name of a Pseudorandom permutation and is responsible for creating a corresponding instance.<p>
	 * It also gets the name of a Padding Scheme. 
	 * A defualt source of randomness is used.
	 * @param prp the name of a specific Pseudorandom permutation, for example "AES".
	 * @param paddingName name of the Padding Scheme to use
	 * @throws FactoriesException 
	 * @throws NoSuchAlgorithmException 
	 */
	public ScCBCEncRandomIV(String prpName, String paddingName) throws FactoriesException, NoSuchAlgorithmException {
		super(prpName);
		this.padding = PaddingFactory.getInstance().getObject(paddingName);
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
	 * The algorithm pseudo-code is: 
	 * 		•	plaintext[0] = prp.invert(cipher[0]) XOR c0
	 *		•	For i from 1 to length of plaintext do:
	 *			o	plaintext[i] : = prp.invert(cipher[i]) XOR ciphertext[i-1]

	 * @param ciphertext the given ciphertext to decrypt
	 * @return the plaintext object containing the decrypted ciphertext
	 */
	@Override
	public Plaintext decrypt(Ciphertext ciphertext) {
		//if the ciphertext is not of type IVCiphertext - throw exception
		if (!(ciphertext instanceof IVCiphertext)){
			throw new IllegalArgumentException("The ciphertext has to be of type IVCiphertext");
		}
		//get the iv and the ciphertext bytes from the IVCiphertext parameters
		byte[] iv = ((IVCiphertext) ciphertext).getIv();
		byte[] cipher = ((SymmetricCiphertext) ciphertext).getBytes();
		
		//prepare a buffer where to store the plaintext, of the same length as the cipher.
		byte[] paddedPlaintext = new byte[cipher.length];
		
		int blockSize = prp.getBlockSize();
		//number of whole blocks
		int numberBlocksInCipher = cipher.length / blockSize;
		
		
		//process the first block plaintext[0] = prp.invertBlock(cipher[0])^IV
		decryptBlock(cipher, 0, iv, 0, paddedPlaintext, 0, blockSize);
		
		//process the other blocks of the cipher. plaintext[i] : = prp.invert(cipher[i]) XOR ciphertext[i-1] 
		int i;
		for (i=1; i<numberBlocksInCipher; i++){
			decryptBlock(cipher, i*blockSize, cipher, (i-1)*blockSize, paddedPlaintext, i*blockSize, blockSize);
		}
		
		byte[] plaintext; //will contain the plaintext without the padding
		//if there is a padding, remove it
		if (!(padding instanceof NoPadding)){
			plaintext = padding.removePad(paddedPlaintext);
		//if there is no padding, plaintext is equal to the padded plaintext
		} else {
			plaintext = paddedPlaintext;
		}
		
		//return the result plaintext
		return new BasicPlaintext(plaintext);
	}
	
	/**
	 * Processes the given block.
	 * This function inverts the cipher using the prp.invertBlock function and 'xores' the result with the iv to get the plaintext.
	 * @param in ciphertext block
	 * @param inOff offset within the ciphertext to take the bytes from
	 * @param iv the bytes to be xored with the inverted cipher block (it can be the IV for the CBC mode of the last cipher block)
	 * @param ivOff offset within the iv to take the bytes from
	 * @param out plaintext block to put the result in
	 * @param outOff offset within the plaintext to put the bytes from
	 * @param size the size of the ciphertext block it can be block size or less
	 */
	private void decryptBlock(byte[] in, int inOff, byte[] iv, int ivOff, byte[] out, int outOff, int size){
		//prepare array that hold the xored bytes in every loop iteration
		byte[] invertBytes = new byte[size];
		
		try {
			prp.invertBlock(in, inOff, invertBytes, 0, prp.getBlockSize());
		
		
			//xor the inbytes with the iv
			for(int i=0; i<size; i++){
				out[outOff + i] = (byte) (iv[ivOff + i] ^ invertBytes[i]);
			}
		} catch (IllegalBlockSizeException e) {
			// shouldn't occur since the arrays are of block size
			Logging.getLogger().log(Level.WARNING, e.toString());
		} 
		
	}

	/**
	 * Encrypts the given plaintext using the CBC mode of operation and the underlying prp as the block cipher function.
	 * The given plaintext can be at any length.
	 * The algorithm pseudo-code is: 
	 * 		•	ciphertext[0] = prp.computeBlock(iv XOR plaintext[0])
	 *		•	for next blocks in plaintext do: //i = 1
	 *			o	ciphertext [i] = prp.computeBlock(ciphertext [i-1] XOR plaintext[i])
	 * @param plaintext the given plaintext to encrypt
	 * @param iv random bytes used in the CBC mode of operation
	 * @return the ciphertext object containing the encrypted plaintext
	 */
	@Override
	protected IVCiphertext encAlg(byte[] plaintext, byte[] iv) {
		byte[] paddedPlaintext; // will contain the padded plaintext
		
		int blockSize = prp.getBlockSize();
		
		// if padding is not "NoPadding", pad the plaintext
		if (!(padding instanceof NoPadding)){
			int numBytesToPad = numBytesToPad(plaintext); // calculate the number of bytes to pad
			paddedPlaintext = padding.pad(plaintext, numBytesToPad);
		} else {
			//if padding is "NoPadding" and the plaintext is not aligned, throw exception
			if ((plaintext.length % blockSize) != 0){
				throw new IllegalArgumentException("plaintext is not aligned to blockSize");
			}
			//if the plaintext is aligned, put it as the padded plaintext
			paddedPlaintext = plaintext;
		}
		
		//prepare the ciphertext array of size equals to the plaintext
		byte[] cipher = new byte[paddedPlaintext.length];
		
		//number of whole blocks
		int numberBlocksInCipher = paddedPlaintext.length / blockSize;
		
		//process the first block cipher[0] = prp.computeBlock(plaintext[0]^iv)
		encryptBlock(paddedPlaintext, 0, iv, 0, cipher, 0, blockSize);
		
		//process the other blocks of the plaintext. ciphertext [i] = prp.computeBlock(ciphertext [i-1] XOR plaintext[i])
		int i;
		for (i=1; i<numberBlocksInCipher; i++){
			encryptBlock(paddedPlaintext, i*blockSize, cipher, (i-1)*blockSize, cipher, i*blockSize, blockSize);
		}
		
		//return an IVCiphertext with the cipher and the IV
		return new IVCiphertext(new BasicSymCiphertext(cipher), iv);
	}
	
	/**
	 * Processes the given block.
	 * This function 'xores' the input with the iv, send it to the prp.computeBlock and put the result in the output array
	 * @param in plaintext block
	 * @param inOff offset within the plaintext to take the bytes from
	 * @param iv the bytes to be xored with the plaintext bytes (it can be the IV for the CBC mode of the last cipher block)
	 * @param ivOff offset within the iv to take the bytes from
	 * @param out ciphertext block to put the result in
	 * @param outOff offset within the ciphertext to put the bytes from
	 * @param size the size of the plaintext block it can be block size or less
	 */
	private void encryptBlock(byte[] in, int inOff, byte[] iv, int ivOff, byte[] out, int outOff, int size){
		//prepare array that hold the xored bytes in every loop iteration
		byte[] xoredBytes = new byte[size];
		
		//xor the inbytes with the iv
		for(int i=0; i<size; i++){
			xoredBytes[i] = (byte) (iv[ivOff + i] ^ in[inOff + i]);
		}
		//compute the prp computeBlock function on the xored bytes. 
		//put the result in the out array
		try {
			prp.computeBlock(xoredBytes, 0, prp.getBlockSize(), out, outOff);
		} catch (IllegalBlockSizeException e) {
			// shouldn't occur since the arrays are of block size
			Logging.getLogger().log(Level.WARNING, e.toString());
		} 
	}

	/**
	 * Calculate the number of bytes to pad.
	 * If the input is aligned, to block size, return block size.
	 * else, number of byts to add in order to align the input to a block size.
	 * @param input array that nedd padding
	 * @return number of bytes to pad
	 */
	private int numBytesToPad(byte[] input){
		int len = input.length;
		int BlockSize = prp.getBlockSize();
		
		//if the array is aligned, return block size
		if (len % BlockSize == 0){
			return BlockSize;
		//if the array is not aligned, return the number of bytes to add in order to be aligned
		} else {
			int bytesInLastBlock = len % BlockSize;
			return BlockSize - bytesInLastBlock;
		}
	}
}
