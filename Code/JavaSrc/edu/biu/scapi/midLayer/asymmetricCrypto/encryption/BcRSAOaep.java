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


package edu.biu.scapi.midLayer.asymmetricCrypto.encryption;

import java.security.InvalidKeyException;
import java.security.KeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.encodings.OAEPEncoding;
import org.bouncycastle.crypto.engines.RSABlindedEngine;

import edu.biu.scapi.exceptions.ScapiRuntimeException;
import edu.biu.scapi.midLayer.ciphertext.ByteArrayAsymCiphertext;
import edu.biu.scapi.midLayer.ciphertext.AsymmetricCiphertext;
import edu.biu.scapi.midLayer.plaintext.ByteArrayPlaintext;
import edu.biu.scapi.midLayer.plaintext.Plaintext;
import edu.biu.scapi.tools.Translation.BCParametersTranslator;

/**
 * RSA-OAEP encryption scheme based on BC library's implementation.
 * By definition, this encryption scheme is CCA-secure and NonMalleable.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class BcRSAOaep extends RSAOaepAbs {
	
	private OAEPEncoding bcBlockCipher;				//The underlying OAEP encoding of BC.
	private CipherParameters privateParameters;		//Parameters contains the private key and the random.
	private CipherParameters publicParameters;		//Parameters contains the public key and the random.
	private boolean forEncryption = true;

	
	/**
	 * Default constructor. Uses default implementation of SecureRandom as source of randomness.
	 */
	public BcRSAOaep(){
		//Calls the constructor with default SecureRandom implementation.
		this(new SecureRandom());
	}
	
	/**
	 * Constructor that lets the user choose the source of randomness.
	 * @param random source of randomness.
	 */
	public BcRSAOaep(SecureRandom random){
		this.random = random;
		//Creates the OAEP encoding with RSABlindedEngine of BC.
		this.bcBlockCipher = new OAEPEncoding(new RSABlindedEngine());

	}
	
	/**
	 * Constructor that lets the user choose the random number generator algorithm.
	 * @param randNumGenAlg random number generator algorithm.
	 * @throws NoSuchAlgorithmException 
	 */
	public BcRSAOaep(String randNumGenAlg) throws NoSuchAlgorithmException{
		this(SecureRandom.getInstance(randNumGenAlg));

	}
	
	/**
	 * Sets this RSAOAEP encryption scheme with a (Public,Private) key pair.
	 * In this case the user can encrypt and decrypt messages.
	 * @param publicKey should be RSAPublicKey.
	 * @param privateKey should be RSAPrivateKey.
	 * @throws InvalidKeyException if the given keys are not instances of RSA keys.
	 */
	@Override
	public void setKey(PublicKey publicKey, PrivateKey privateKey) throws InvalidKeyException{
		//Keys should be RSA keys.
		if(!(publicKey instanceof RSAPublicKey)){
			throw new InvalidKeyException("keys should be instances of RSA keys");
		}
		if(privateKey!= null && !(privateKey instanceof RSAPrivateKey)){
				throw new InvalidKeyException("keys should be instances of RSA keys");
		}
				
		//Notice! We set the public key twice - in the PublicKey member and in the publicParameters object.
		//This can lead to many synchronization problems, so we need to be very careful not to change just one of them.
		this.publicKey = (RSAPublicKey) publicKey;
		
		//Creates BC objects and initializes them.
		initBCCipher((RSAPublicKey) publicKey, (RSAPrivateKey)privateKey);
		isKeySet = true;
	}



	/**
	 * Sets this RSAOAEP encryption scheme only with public key.
	 * In this case the user can encrypt messages but can not decrypt messages.
	 * @param publicKey should be RSAPublicKey
	 * @throws InvalidKeyException if the given key is not instance of RSAPublickey.
	 */
	@Override
	public void setKey(PublicKey publicKey) throws InvalidKeyException {
		setKey(publicKey, null);
	}
	
	/**
	 * Translates the keys and random to BC CipherParameters and initializes BC object in encrypt mode.
	 * In order to decrypt, the decrypt function initializes them again to decrypt mode.
	 * @param privateKey 
	 * @param publicKey 
	 */
	private void initBCCipher(RSAPublicKey publicKey, RSAPrivateKey privateKey){
		
		//Translates the keys and random to BC parameters.
		if (privateKey != null){
			privateParameters = BCParametersTranslator.getInstance().translateParameter(privateKey, random);
		}
		publicParameters = BCParametersTranslator.getInstance().translateParameter(publicKey, random);
		//Initializes the OAEP object with the cipherPerameters and for encryption.
		bcBlockCipher.init(forEncryption, publicParameters);
	}
	
	/**
	 * Returns the maximum size of the byte array that can be passed to generatePlaintext function. 
	 * This is the maximum size of a byte array that can be converted to a Plaintext object suitable to this encryption scheme.
	 * @return the maximum size of the byte array that can be passed to generatePlaintext function. 
	 */
	public int getMaxLengthOfByteArrayForPlaintext(){
		return bcBlockCipher.getInputBlockSize();
	}
	
	/**
	 * Encrypts the given plaintext according to the RSAOAEP algorithm using BC OAEPEncoding.
	 * @param plaintext the plaintext to encrypt. MUST be an instance of ByteArrayPlaintext.
	 * @return Ciphertext contains the encrypted plaintext
	 * @throws IllegalStateException if no public key was set.
	 * @throws IllegalArgumentException if the given Plaintext is not instance of ByteArrayPlaintext.
	 * @throws ScapiRuntimeException if the exception InvalidCipherTextException of BC is thrown. This exception is thrown when there is something unexpected in a message.
	 */
	@Override
	public AsymmetricCiphertext encrypt(Plaintext plaintext){	
		//If there is no public key can not encrypt, throws exception.
		if (!isKeySet()){
			throw new IllegalStateException("in order to encrypt a message this object must be initialized with public key");
		}
		
		if (!(plaintext instanceof ByteArrayPlaintext)){
			throw new IllegalArgumentException("plaintext should be instance of ByteArrayPlaintext");
		}
		//If the underlying BC object used to the encryption is in decrypt mode - changes it.
		if (!forEncryption){
			forEncryption = true;
			bcBlockCipher.init(forEncryption, publicParameters);
		}
		
		byte[] plaintextBytes = ((ByteArrayPlaintext) plaintext).getText(); //Gets the plaintext bytes.
		
		byte[] ciphertext;
		try {
			//Encrypts the plaintext using BC OAEP object.
			ciphertext = bcBlockCipher.encodeBlock(plaintextBytes, 0, plaintextBytes.length);
		} catch (InvalidCipherTextException e) {
			throw new ScapiRuntimeException(e.getMessage());
		}

		//Returns a ciphertext with the encrypted plaintext.
		return new ByteArrayAsymCiphertext(ciphertext);
	}

	/**
	 * Decrypts the given ciphertext according to the RSAOAEP algorithm using BC OAEPEncoding.
	 * @param cipher the ciphertext to decrypt. Must be an instance of BasicAsymCiphertext.
	 * @return Plaintext contains the decrypted ciphertext.
	 * @throws KeyException if no private key was set.
	 * @throws IllegalArgumentException if the given cipher is not instance of BasicAsymCiphertext.
	 * @throws ScapiRuntimeException if the exception InvalidCipherTextException of BC is thrown. This exception is thrown when there is something unexpected in a message.
	 */
	@Override
	public Plaintext decrypt(AsymmetricCiphertext cipher) throws KeyException{
		//If there is no private key can not decrypt, throws exception.
		if (privateParameters == null){
			throw new KeyException("in order to decrypt a message, this object must be initialized with private key");
		}
		//Cipher must be of type BasicAsymCiphertext.
		if (!(cipher instanceof ByteArrayAsymCiphertext)){
			throw new IllegalArgumentException("The ciphertext has to be of type BasicAsymCiphertext");
		}
		//If the underlying BC object used to the decryption is in encrypt mode - changes it.
		if (forEncryption){
			forEncryption = false;
			bcBlockCipher.init(forEncryption, privateParameters);
		}
		
		byte[] ciphertext = ((ByteArrayAsymCiphertext) cipher).getBytes();

		byte[] plaintext;
		try {
			//Decrypts the ciphertext using BC OAEP object.
			plaintext = bcBlockCipher.decodeBlock(ciphertext, 0, ciphertext.length);
		} catch (InvalidCipherTextException e) {
			throw new ScapiRuntimeException(e.getMessage());
		}
		//Returns a plaintext with the decrypted ciphertext.
		return new ByteArrayPlaintext(plaintext);
	}

	
}
