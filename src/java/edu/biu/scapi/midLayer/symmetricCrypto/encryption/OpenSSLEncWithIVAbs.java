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

import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import edu.biu.scapi.midLayer.ciphertext.ByteArraySymCiphertext;
import edu.biu.scapi.midLayer.ciphertext.IVCiphertext;
import edu.biu.scapi.midLayer.ciphertext.SymmetricCiphertext;
import edu.biu.scapi.midLayer.plaintext.ByteArrayPlaintext;
import edu.biu.scapi.midLayer.plaintext.Plaintext;
import edu.biu.scapi.primitives.prf.PseudorandomPermutation;

/**
 * This is an abstract class that manage the common behavior of symmetric encryption using Open SSL library. 
 * We implemented symmetric encryption using OpenSSL with two modes of operations - CBC and CTR, each one has a unique derived class.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public abstract class OpenSSLEncWithIVAbs implements SymmetricEnc{

	protected long enc;							// A pointer to the native object that implements the encryption.
	protected long dec;							// A pointer to the native object that implements the decryption.
	private boolean isKeySet; 
	private SecureRandom random;				// Used to generate a SecretKey and IV if necessary.
	protected String prpName;					// The name of the underlying prp to use.
	
	//Native functions that call the JNI architecture in order to use OpenSSL functions.
	private native long createEncryption();		// Create the native object that does the encryption.
	private native long createDecryption();		// Create the native object that does the decryption.
	private native int getIVSize(long enc);		// Return the size of the Iv in the current encryption scheme.
	private native byte[] encrypt(long enc, byte[] plaintext, byte[] iv);	//Encrypt the given plaintext.
	private native byte[] decrypt(long dec, byte[] cipher, byte[] iv);		//Decrypt the given ciphertext.
	private native void deleteNative(long enc, long dec);					//Delete teh native objects.
	
	/**
	 * Gets the name of the underlying prp that determines the type of encryption that will be performed.
	 * A default source of randomness is used.
	 * @param prp the underlying pseudorandom permutation to get the name of.
	 */
	public OpenSSLEncWithIVAbs(PseudorandomPermutation prp) {
		this(prp.getAlgorithmName(), new SecureRandom());
	}
	
	/**
	 * Gets the name of the underlying prp that determines the type of encryption that will be performed.
	 * The random passed to this constructor determines the source of randomness that will be used.
	 * @param prp the underlying pseudorandom permutation to get the name of.
	 * @param random a user provided source of randomness.
	 */
	public OpenSSLEncWithIVAbs(PseudorandomPermutation prp, SecureRandom random) {
		this(prp.getAlgorithmName(), random);
	}
	
	
	/**
	 * Sets the name of a Pseudorandom permutation and the name of a Random Number Generator Algorithm to use to generate the source of randomness.<p>
	 * @param prpName the name of a specific Pseudorandom permutation, for example "AES".
	 * @param randNumGenAlg  the name of the RNG algorithm, for example "SHA1PRNG".
	 * @throws NoSuchAlgorithmException  if the given randNumGenAlg is not a valid random number generator.
	 */
	public OpenSSLEncWithIVAbs(String prpName, String randNumGenAlg) throws NoSuchAlgorithmException {
		this(prpName, SecureRandom.getInstance(randNumGenAlg));
		
	}
	
	/**
	 * Sets the name of a Pseudorandom permutation and the source of randomness.<p>
	 * The given prpName should be a name of prp algorithm such that OpenSSL provides an encryption with.
	 * The following names are valid:
	 * For CBC mode of operations: AES and TripleDES.
	 * For CTR mode of operations: AES.
	 * @param prpName the name of a specific Pseudorandom permutation, for example "AES".
	 * @param random  a user provided source of randomness.
	 * @throw IllegalArgumentException in case the given prpName is not valid for this encryption scheme.
	 */
	public OpenSSLEncWithIVAbs(String prpName, SecureRandom random) {
		//Check that the given prp name is a valid algorithm for this encryption scheme.
		//Open SSL provides implementations only for AES and TripleDES in CBC mode 
		//and only for AES in CTR mode.
		if (!checkExistance(prpName)){
			throw new IllegalArgumentException("The given prp name is not supported in this encryption mode.");
		}
		
		//Create native objects for encryption and decryption.
		enc = createEncryption();
		dec = createDecryption();
		
		//Set the other parameters.
		this.prpName = prpName;
		this.random = random;
		
	}

	//Check that the given name is valid for this encryption scheme.
	protected abstract boolean checkExistance(String prpName);
	
	/**
	 * Supply the encryption scheme with a Secret Key.
	 */
	public void setKey(SecretKey secretKey) throws InvalidKeyException{
		int len = secretKey.getEncoded().length*8;
		
		//The key size should suit the encryption type. 
		//In case the underlying prp is TripleDES, the key should be 128 or 192 bits long.
		//In case the underlying prp is AES, the key should be 128, 192 or 256 bits long.
		if (len != 128 && len != 192){
			if ((len != 256) && (prpName.equals("AES"))){
				throw new InvalidKeyException("AES key size should be 128/192/256 bits long");
			} else if (prpName.equals("TripleDES")){
				throw new InvalidKeyException("TripleDES key size should be 128/192 bits long");
			}
		}
		
		isKeySet = true;
	}

	/**
	 * Checks if this object has been given a SecretKey.
	 * @return true, if already initialized; False, otherwise.
	 * 
	 */
	public boolean isKeySet(){
		return isKeySet;
	}
	
	
	/**
	 * This function should not be used to generate a key for the encryption and it throws UnsupportedOperationException.
	 * @throws UnsupportedOperationException 
	 */
	@Override
	public SecretKey generateKey(AlgorithmParameterSpec keyParams) throws UnsupportedOperationException {
		throw new UnsupportedOperationException("To generate a key for this encryption object use the generateKey(int keySize) function");
	}

	/**
	 * Generates a secret key to initialize the underlying PRP object.
	 * @param keySize is the required secret key size in bits.
	 * @return the generated secret key.
	 */
	@Override
	public SecretKey generateKey(int keySize) {
		SecretKey secretKey = null;
		//Looks for a default provider implementation of the key generation for PRP. 
		try {
			//Gets the KeyGenerator of this algorithm,
			KeyGenerator keyGen = KeyGenerator.getInstance(prpName);
			//If the key size is zero or less - uses the default key size as implemented in the provider implementation,
			if(keySize <= 0){
				keyGen.init(random);
			//Else, uses the keySize to generate the key.
			} else {
				keyGen.init(keySize, random);
			}
			//Generates the key.
			secretKey = keyGen.generateKey();
		
		//Could not find a default provider implementation.
		//Then, generate a random string of bits of length keySize, which has to be greater than zero. 
		} catch (NoSuchAlgorithmException e) {
			//If the key size is zero or less - throw exception.
			if (keySize <= 0){
				throw new NegativeArraySizeException("Key size must be greater than 0");
			}
			if ((keySize % 8) != 0)  {
				throw new InvalidParameterException("Wrong key size: must be a multiple of 8");
			}	              

			//Creates a byte array of size keySize.
			byte[] genBytes = new byte[keySize/8];

			//Generates the bytes using the random.
			random.nextBytes(genBytes);
			//Creates a secretKey from the generated bytes.
			secretKey = new SecretKeySpec(genBytes, "");
		}
		
		return secretKey;
	}
	
	/**
	 * This function encrypts a plaintext. It lets the system choose the random IV.
	 * @param plaintext should be an instance of ByteArrayPlaintext.
	 * @return  an IVCiphertext, which contains the IV used and the encrypted data.
	 * @throws IllegalStateException if no secret key was set.
	 * @throws IllegalArgumentException if the given plaintext is not an instance of ByteArrayPlaintext.
	 */
	public SymmetricCiphertext encrypt(Plaintext plaintext) {	
		if (!isKeySet()){
			throw new IllegalStateException("no SecretKey was set");
		}
		
		//Allocate space for the IV.
		byte[] iv = new byte[getIVSize(enc)];
		//Generate a random IV.
		this.random.nextBytes(iv);
		
		//Encrypt the plaintext with the just chosen random IV.
		IVCiphertext cipher = null;
		try {
			cipher =  (IVCiphertext) encrypt(plaintext, iv);
		} catch (IllegalBlockSizeException e) {
			//Should not occur since IV was created of size Block size.
			e.printStackTrace();
		}
		return cipher;
	}
	
	/**
	 * This function encrypts a plaintext. It lets the user choose the random IV.
	 * @param plaintext should be an instance of ByteArrayPlaintext.
	 * @param iv random bytes to use in the encryption of the message.
	 * @return an IVCiphertext, which contains the IV used and the encrypted data. 
	 * @throws IllegalStateException if no secret key was set.
	 * @throws IllegalArgumentException if the given plaintext is not an instance of ByteArrayPlaintext.
	 * @throws IllegalBlockSizeException if the given IV length is not as the block size.
	 */
	public SymmetricCiphertext encrypt(Plaintext plaintext, byte[] iv) throws IllegalBlockSizeException{
		if (!isKeySet()){
			throw new IllegalStateException("no SecretKey was set");
		}
		//Check validity of IV's length:
		if(iv.length != getIVSize(enc)){
			
			throw new IllegalBlockSizeException("The length of the IV passed is not equal to the block size of current PRP");
		}
		if (!(plaintext instanceof ByteArrayPlaintext)){
			throw new IllegalArgumentException("plaintext should be instance of ByteArrayPlaintext");
		}
		
		//Call the native function that idoes the encryption. 
		ByteArrayPlaintext text = (ByteArrayPlaintext)plaintext;
		byte[] cipher = encrypt(enc, text.getText(), iv);

		//Create and return an IVCiphertext with the iv and encrypted data.
		return new IVCiphertext(new ByteArraySymCiphertext(cipher), iv);
	}

	/**
	 * Decrypts the given ciphertext using the underlying prp as the block cipher function.
	 * 
	 * @param ciphertext the given ciphertext to decrypt. MUST be an instance of IVCiphertext.
	 * @return the plaintext object containing the decrypted ciphertext.
	 * @throws IllegalStateException if no secret key was set.
	 * @throws IllegalArgumentException if the given ciphertext is not an instance of IVCiphertext.
	 */
	@Override
	public Plaintext decrypt(SymmetricCiphertext ciphertext) {
		
		if (!isKeySet()){
			throw new IllegalStateException("no SecretKey was set");
		}
		
		//If the ciphertext is not of type IVCiphertext - throw exception.
		if (!(ciphertext instanceof IVCiphertext)){
			throw new IllegalArgumentException("The ciphertext has to be of type IVCiphertext");
		}
		
		//Gets the iv and the ciphertext bytes from the IVCiphertext parameters.
		byte[] iv = ((IVCiphertext) ciphertext).getIv();
		byte[] cipher = ciphertext.getBytes();
		
		//Call the native funcrion that does the decryption.
		byte[] plaintext = decrypt(dec, cipher, iv);
		 
		return new ByteArrayPlaintext(plaintext);
	}
	
	/**
	 * Deletes the native objects.
	 */
	protected void finalize() throws Throwable {

		// Delete from the dll the dynamic allocation.
		deleteNative(enc, dec);

		super.finalize();
	}

	static {
		//loads the OpenSSL dll.
		 System.loadLibrary("OpenSSLJavaInterface");
	}
}
