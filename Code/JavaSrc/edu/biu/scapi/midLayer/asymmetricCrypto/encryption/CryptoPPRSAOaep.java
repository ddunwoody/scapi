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

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import edu.biu.scapi.midLayer.ciphertext.ByteArrayAsymCiphertext;
import edu.biu.scapi.midLayer.ciphertext.AsymmetricCiphertext;
import edu.biu.scapi.midLayer.plaintext.ByteArrayPlaintext;
import edu.biu.scapi.midLayer.plaintext.Plaintext;

/**
 * RSA-OAEP encryption scheme based on Crypto++ library's implementation.
 * By definition, this encryption scheme is CCA-secure and NonMalleable.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class CryptoPPRSAOaep extends RSAOaepAbs {
	
	private long encryptor; //Pointer to encryptor object (RSAES_OAEP_SHA_Encryptor) in Crypto++.
	private long decryptor; //Pointer to decryptor object (RSAES_OAEP_SHA_Decryptor) in Crypto++.
	private boolean isPrivateKeySet;
	
	//Native functions that compute the encryption scheme functionality.
	private native long createRSAEncryptor();
	private native long createRSADecryptor();
	private native void initRSAEncryptor(long encryptor, byte[] modulus, byte[] exponent);
	//Used to initialize the decryptor object if the given private key contains N, e, d.
	private native void initRSADecryptor(long decryptor, byte[] modulus, byte[] exponent, byte[] d);
	//Used to initialize the decryptor object if the given private key is RSA-CRT key which contain N, e, d, p, q, dp, dq, crt.
	private native void initRSACrtDecryptor(long decryptor, byte[] modulus, byte[] exponent, byte[] d, byte[] p, byte[] q, byte[] dp, byte[]dq, byte[] crt);
	
	private native byte[] doEncrypt(long encryptor, byte[] plaintext);
	private native byte[] doDecrypt(long decryptor, byte[] ciphertext);
	
	private native int getPlaintextLength(long encryptor); 
	private native void deleteRSA(long encryptor, long decryptor);	//Delete the native RSA object.
	
	/**
	 * Default constructor. Uses default implementation of SecureRandom as source of randomness.
	 */
	public CryptoPPRSAOaep(){
		//Calls the constructor with default SecureRandom implementation.
		this(new SecureRandom());
	}
	
	/**
	 * Constructor that lets the user choose the random number generator algorithm.
	 * @param randNumGenAlg random number generator algorithm.
	 * @throws NoSuchAlgorithmException 
	 */
	public CryptoPPRSAOaep(String randNumGenAlg) throws NoSuchAlgorithmException{
		this(SecureRandom.getInstance(randNumGenAlg));

	}
	
	/**
	 * Constructor that lets the user choose the source of randomness.
	 * @param secureRandom source of randomness.
	 */
	public CryptoPPRSAOaep(SecureRandom secureRandom){
		this.random = secureRandom;
		
		//Creates the native encryptor object.
		this.encryptor = createRSAEncryptor();
		//Creates the native decryptor object.
		this.decryptor = createRSADecryptor();
	}
		
	/**
	 * Sets this RSAOAEP encryption scheme with a (Public,Private) key pair.
	 * In this case the user can encrypt and decrypt messages.
	 * @param publicKey should be RSAPublicKey.
	 * @param privateKey should be RSAPrivateKey.
	 * @throws InvalidKeyException if the given keys are not instances of RSA keys.
	 */
	@Override
	public void setKey(PublicKey publicKey, PrivateKey privateKey) throws InvalidKeyException {
		
		//Keys should be RSA keys.
		if(!(publicKey instanceof RSAPublicKey)){
			throw new InvalidKeyException("keys should be instances of RSA keys");
		}
		if(privateKey!= null && !(privateKey instanceof RSAPrivateKey)){
				throw new InvalidKeyException("keys should be instances of RSA keys");
		}
		
		//Notice! We set the public key twice - in the PublicKey member and in the native encryptor object.
		//This can lead to many synchronization problems, so we need to be very careful not to change just one of them.
		this.publicKey = (RSAPublicKey) publicKey;
		
		// Gets the values of modulus (N), pubExponent (e), 
		BigInteger pubExponent = ((RSAPublicKey) publicKey).getPublicExponent();
		BigInteger modN = ((RSAKey) publicKey).getModulus();
		
		//Initializes the native encryptor object with N, e.
		initRSAEncryptor(encryptor, modN.toByteArray(), pubExponent.toByteArray());
		
		if (privateKey != null){
			
			//Gets the value of privExponent(d)
			BigInteger privExponent = ((RSAPrivateKey) privateKey).getPrivateExponent();
			//If private key is CRT private key.
			if (privateKey instanceof RSAPrivateCrtKey)
			{
				//Gets all the crt parameters.
				RSAPrivateCrtKey key = (RSAPrivateCrtKey) privateKey;
				BigInteger p = key.getPrimeP();
				BigInteger q = key.getPrimeQ();
				BigInteger dp = key.getPrimeExponentP();
				BigInteger dq = key.getPrimeExponentQ();
				BigInteger crt = key.getCrtCoefficient();
				
				//Initializes the native decryptor object.
				initRSACrtDecryptor(decryptor, modN.toByteArray(), pubExponent.toByteArray(), privExponent.toByteArray(), 
						p.toByteArray(), q.toByteArray(), dp.toByteArray(), dq.toByteArray(), crt.toByteArray());
				
			//If private key is key with N, e, d.
			} else {
				
				//Initializes the native decryptor object with the RSA parameters - n, e, d.
				initRSADecryptor(decryptor, modN.toByteArray(), pubExponent.toByteArray(), privExponent.toByteArray());
			}
			
			isPrivateKeySet = true;
		}
		
		isKeySet = true;
	}

	/**
	 * Sets this RSAOAEP encryption scheme only with public key.
	 * In this case the user can encrypt messages but can not decrypt messages.
	 * @param publicKey should be RSAPublicKey.
	 * @throws InvalidKeyException if the given key is not instance of RSAPublickey.
	 */
	@Override
	public void setKey(PublicKey publicKey) throws InvalidKeyException {
		setKey(publicKey, null);
	}

	/**
	 * Returns the maximum size of the byte array that can be passed to generatePlaintext function. 
	 * This is the maximum size of a byte array that can be converted to a Plaintext object suitable to this encryption scheme.
	 * @return the maximum size of the byte array that can be passed to generatePlaintext function. 
	 */
	public int getMaxLengthOfByteArrayForPlaintext(){
		return getPlaintextLength(encryptor);
	}
	
	/**
	 * Encrypts the given plaintext according to the RSAOAEP algorithm using Crypto++ implementation.
	 * @param plaintext the plaintext to encrypt. MUST be an instance of ByteArrayPlaintext.
	 * @return Ciphertext contains the encrypted plaintext.
	 * @throws IllegalStateException if no public key was set.
	 * @throws IllegalArgumentException if the given Plaintext is not instance of ByteArrayPlaintext.
	 * 
	 */
	@Override
	public AsymmetricCiphertext encrypt(Plaintext plaintext){
		// If there is no public key can not encrypt, throws exception.
		if (!isKeySet()){
			throw new IllegalStateException("in order to encrypt a message this object must be initialized with public key");
		}
		
		if (!(plaintext instanceof ByteArrayPlaintext)){
			throw new IllegalArgumentException("plaintext should be instance of ByteArrayPlaintext");
		}
		
		// Calls native function that computes the encryption.
		byte[] ciphertext = doEncrypt(encryptor, ((ByteArrayPlaintext)plaintext).getText());
		// Returns a ciphertext with the encrypted plaintext.
		return new ByteArrayAsymCiphertext(ciphertext);
	}

	/**
	 * Decrypts the given ciphertext according to the RSAOAEP algorithm using Crypto++ implementation.
	 * @param cipher the ciphertext to decrypt. Must be an instance of BasicAsymCiphertext.
	 * @return Plaintext contains the decrypted ciphertext.
	 * @throws KeyException if no private key was set.
	 * @throws IllegalArgumentException if the given cipher is not instance of BasicAsymCiphertext.
	 */
	@Override
	public Plaintext decrypt(AsymmetricCiphertext cipher) throws KeyException{
		
		// If there is no private key can not decrypt, throws exception.
		if (!isPrivateKeySet){
			throw new KeyException("in order to decrypt a message, this object must be initialized with private key");
		}
		// Cipher must be of type BasicAsymCiphertext.
		if (!(cipher instanceof ByteArrayAsymCiphertext)){
			throw new IllegalArgumentException("The ciphertext has to be of type BasicAsymCiphertext");
		}
		
		// Calls native function that computes the decryption.
		byte[] plaintext =  doDecrypt(decryptor, ((ByteArrayAsymCiphertext)cipher).getBytes());
		return new ByteArrayPlaintext(plaintext);
	}
	
	/*
	 * Delete the related RSA object.
	 */
	protected void finalize() throws Throwable {

		// Delete from the dll the dynamic allocation of the RSA object.
		deleteRSA(encryptor, decryptor);

	}
	
	static {
	       System.loadLibrary("CryptoPPJavaInterface");
	}
}
