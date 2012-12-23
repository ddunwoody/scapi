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
/**
 * This class implements common functionality of Symmetric Encryption Schemes that must use a random IV.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 */
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;

import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.midLayer.ciphertext.IVCiphertext;
import edu.biu.scapi.midLayer.ciphertext.SymmetricCiphertext;
import edu.biu.scapi.midLayer.plaintext.ByteArrayPlaintext;
import edu.biu.scapi.midLayer.plaintext.Plaintext;
import edu.biu.scapi.primitives.prf.PseudorandomPermutation;
import edu.biu.scapi.primitives.prf.bc.BcAES;
import edu.biu.scapi.tools.Factories.PrfFactory;

abstract class EncWithIVAbs implements SymmetricEnc {
	protected PseudorandomPermutation prp;
	protected SecureRandom random;
	
	
	/**
	 * Default constructor. Uses default implementation of prp and SecureRandom.
	 */
	public EncWithIVAbs(){
		//Calls the general constructor with AES and default SecureRandom object.
		this(new BcAES(), new SecureRandom());
	}
	
	/**
	 * By passing a specific Pseudorandom permutation we are setting the type of encryption scheme.<p>
	 * A default source of randomness is used.
	 * @param prp specific Pseudorandom permutation, for example AES.
	 */
	public EncWithIVAbs(PseudorandomPermutation prp){
		//Calls the general constructor with the given prp and default SecureRandom object.
		this(prp, new SecureRandom());
	}
	
	/**
	 * By passing a specific Pseudorandom permutation we are setting the type of encryption scheme.<p>
	 * Random object sets the source of randomness.
	 * @param prp the specific Pseudorandom permutation.
	 * @param random SecureRandom object to set the random member
	 */
	public EncWithIVAbs(PseudorandomPermutation prp, SecureRandom random) {
		//Sets the prp and random.
		this.prp = prp;
		this.random = random;
	}
	
	/**
	 * By passing a specific Pseudorandom permutation we are setting the type of encryption scheme.<p>
	 * This constructor gets the name of a Pseudorandom permutation and is responsible for creating a corresponding instance.<p>
	 * A default source of randomness is used.
	 * @param prpName the name of a specific Pseudorandom permutation, for example "AES".
	 * @throws FactoriesException if the given name is not a valid prp name.
	 */
	public EncWithIVAbs(String prpName) throws FactoriesException {
		//Creates a prp using the factory and calls the general constructor with it.
		this((PseudorandomPermutation) PrfFactory.getInstance().getObject(prpName));
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
	public EncWithIVAbs(String prpName, String randNumGenAlg) throws FactoriesException, NoSuchAlgorithmException {
		//Creates a prp and a SecureRandom object using the factories and calls the general constructor with the created objects.
		this((PseudorandomPermutation) PrfFactory.getInstance().getObject(prpName), SecureRandom.getInstance(randNumGenAlg));
	}
	
	
	/**
	 * Supply the encryption scheme with a Secret Key.
	 */
	public void setKey(SecretKey secretKey) throws InvalidKeyException{
		prp.setKey(secretKey); 
	}

	/**
	 * Checks if this object has been given a SecretKey .
	 * @return true, if already initialized. <p> false, otherwise.
	 * 
	 */
	public boolean isKeySet(){
		return prp.isKeySet();
	}
	
	
	/**
	 * Generates a secret key to initialize this encryption with IV object.
	 * This function delegates the generation of the key to the underlying PRP. 
	 * It should only be used if the Secret Key is not a string of random bits of a specified length.
	 * @param keyParams parameters needed to create the key.
	 * @return the generated secret key
	 * @throws InvalidParameterSpecException if hte given keyParams does not match the prp type.
	 */
	public SecretKey generateKey(AlgorithmParameterSpec keyParams ) throws InvalidParameterSpecException{
		//Delegates the key generation to the prp object.
		return prp.generateKey(keyParams);
	}
	
	/**
	 * Generates a secret key to initialize this encryption with IV object.
	 * @param keySize the length of the key to generate.
	 * @return the generated secret key
	 */
	public SecretKey generateKey(int keySize) {
		//Delegates the key generation to the prp object.
		return prp.generateKey(keySize);
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
		//Allocates space for the IV.
		byte[] iv = new byte[prp.getBlockSize()];
		//Generates a random IV
		this.random.nextBytes(iv);
		
		//Encrypts the plaintext with the just chosen random IV.
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
	 * @param iv random bytes to use in the encryption pf the message.
	 * @return an IVCiphertext, which contains the IV used and the encrypted data. 
	 * @throws IllegalStateException if no secret key was set.
	 * @throws IllegalArgumentException if the given plaintext is not an instance of ByteArrayPlaintext.
	 * @throws IllegalBlockSizeException if the given IV length is not as the block size.
	 */
	public SymmetricCiphertext encrypt(Plaintext plaintext, byte[] iv) throws IllegalBlockSizeException{
		if (!isKeySet()){
			throw new IllegalStateException("no SecretKey was set");
		}
		//Checks validity of IV's length:
		if(iv.length != prp.getBlockSize()){
			throw new IllegalBlockSizeException("The length of the IV passed is not equal to the block size of current PRP");
		}
		if (!(plaintext instanceof ByteArrayPlaintext)){
			throw new IllegalArgumentException("plaintext should be instance of ByteArrayPlaintext");
		}
		//Each implementing class must write the actual encryption algorithm in "encAlg" function. 
		ByteArrayPlaintext text = (ByteArrayPlaintext)plaintext;
		IVCiphertext cipher =  encAlg(text.getText(),iv);
		return cipher;
	}
	

	//This protected function must be implemented in each concrete class.
	//In CTREnc this function performs the CTR mode of operation.
	//In CBCEnc this function performs the CBC mode of operation.
	protected abstract IVCiphertext encAlg(byte[] plaintext, byte[] iv);

	
}
