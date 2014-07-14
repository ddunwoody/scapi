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
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.RSAKeyGenParameterSpec;

import edu.biu.scapi.midLayer.asymmetricCrypto.keys.KeySendableData;
import edu.biu.scapi.midLayer.ciphertext.AsymmetricCiphertext;
import edu.biu.scapi.midLayer.ciphertext.AsymmetricCiphertextSendableData;
import edu.biu.scapi.midLayer.ciphertext.ByteArrayAsymCiphertext;
import edu.biu.scapi.midLayer.plaintext.ByteArrayPlaintext;
import edu.biu.scapi.midLayer.plaintext.Plaintext;

/**
 * Abstract class of RSA OAEP encryption scheme. This class has some common functionality of the encryption scheme, such as key generation.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public abstract class RSAOaepAbs implements RSAOaepEnc {

	protected SecureRandom random;		//Source of randomness.
	protected boolean isKeySet;
	protected RSAPublicKey publicKey;
	
	@Override
	public boolean isKeySet() {
		return isKeySet;
	}
	
	/**
	 * Returns the PublicKey of this RSA encryption scheme.
	 * This function should not be use to check if the key has been set. 
	 * To check if the key has been set use isKeySet function.
	 * @return the RSAPublicKey
	 * @throws IllegalStateException if no public key was set.
	 */
	public PublicKey getPublicKey(){
		if (!isKeySet()){
			throw new IllegalStateException("no PublicKey was set");
		}
		
		return publicKey;
	}

	/**
	 * @return the name of this Asymmetric encryption - "RSA/OAEP".
	 */
	@Override
	public String getAlgorithmName() {
		return "RSA/OAEP";
	}

	/**
	 * RSA OAEP has a limit of the byte array length to generate a plaintext from.
	 * @return true. 
	 */
	public boolean hasMaxByteArrayLengthForPlaintext(){
		return true;
	}
	
	/**
	 * Generates a Plaintext suitable to RSA/Oaep encryption scheme from the given message.
	 * @param text byte array to convert to a Plaintext object.
	 * @throws IllegalArgumentException if the given message's length is greater than the maximum. 
	 */
	public Plaintext generatePlaintext(byte[] text){
		if (text.length > getMaxLengthOfByteArrayForPlaintext()){
			throw new IllegalArgumentException("the given text is too big for plaintext");
		}
		
		return new ByteArrayPlaintext(text);
	}
	
	/**
	 * Generates a byte array from the given plaintext. 
	 * This function should be used when the user does not know the specific type of the Asymmetric encryption he has, 
	 * and therefore he is working on byte array.
	 * @param plaintext to generates byte array from. MUST be an instance of ByteArrayPlaintext.
	 * @return the byte array generated from the given plaintext.
	 * @throws IllegalArgumentException if the given plaintext is not an instance of ByteArrayPlaintext.
	 */
	public byte[] generateBytesFromPlaintext(Plaintext plaintext){
		if (!(plaintext instanceof ByteArrayPlaintext)){
			throw new IllegalArgumentException("plaintext should be an instance of ByteArrayPlaintext");
		}
		
		return ((ByteArrayPlaintext) plaintext).getText();
	}

	/**
	 * This function is not supported. 
	 */
	@Override
	public KeyPair generateKey() {
		throw new UnsupportedOperationException("To generate RSA keys call generateKey with RSAKeyGenParameterSpec");
	}

	
	/**
	 * Generate an RSA key pair using the given parameters.
	 * @param keyParams RSAKeyGenParameterSpec
	 * @return KeyPair contains keys for this RSAOaep object
	 * @throws InvalidParameterSpecException if keyParams is not instance of RSAKeyGenParameterSpec
	 */
	public KeyPair generateKey(AlgorithmParameterSpec keyParams) throws InvalidParameterSpecException {
		//If keyParams is not the expected, throw exception.
		if (!(keyParams instanceof RSAKeyGenParameterSpec)){
			throw new InvalidParameterSpecException("keyParams should be instance of RSAKeyGenParameterSpec");
		}
		
		try {
			//Generates keys using the KeyPairGenerator
			KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
			generator.initialize(keyParams, random);
			return generator.generateKeyPair(); 
		} catch(InvalidAlgorithmParameterException e){
			//Shouldn't occur since the parameterSpec is valid for RSA
		} catch (NoSuchAlgorithmException e) {
			//Shouldn't occur since RSA is a valid algorithm
			e.printStackTrace();
		}
		return null;
	}
	
	/**
	 * Encrypts the given plaintext using this asymmetric encryption scheme and using the given random value.<p>
	 * All our implementations of RSA OAEP are done throw other libraries that do not provide a way to give the random 
	 * value used to encrypt. For that reason, we throw an exception.
	 * @throws UnsupportedOperationException.
	 */
	@Override
	public AsymmetricCiphertext encrypt(Plaintext plainText, BigInteger r){
		throw new UnsupportedOperationException("RSA OAEP implementations do not provide a way to give the random value to use in the encryption");
	}
	
	/** (non-Javadoc)
	 * @see edu.biu.scapi.midLayer.asymmetricCrypto.encryption.AsymmetricEnc#generateCiphertext(edu.biu.scapi.midLayer.ciphertext.AsymmetricCiphertextSendableData)
	 * @deprecated As of SCAPI-V1-0-2-2 use reconstructCiphertext(AsymmetricCiphertextSendableData data)
	 */
	@Override
	@Deprecated public AsymmetricCiphertext generateCiphertext(	AsymmetricCiphertextSendableData data) {
		if(! (data instanceof ByteArrayAsymCiphertext))
			throw new IllegalArgumentException("The input data has to be of type ByteArrayAsymCiphertext");

		return (ByteArrayAsymCiphertext) data;
	}
	
	/* (non-Javadoc)
	 * @see edu.biu.scapi.midLayer.asymmetricCrypto.encryption.AsymmetricEnc#reconstructCiphertext(edu.biu.scapi.midLayer.ciphertext.AsymmetricCiphertextSendableData)
	 */
	@Override
	public AsymmetricCiphertext reconstructCiphertext(	AsymmetricCiphertextSendableData data) {
		if(! (data instanceof ByteArrayAsymCiphertext))
			throw new IllegalArgumentException("The input data has to be of type ByteArrayAsymCiphertext");

		return (ByteArrayAsymCiphertext) data;
	}
	
	
	/* (non-Javadoc)
	 * @see edu.biu.scapi.midLayer.asymmetricCrypto.encryption.AsymmetricEnc#reconstructPrivateKey(edu.biu.scapi.midLayer.asymmetricCrypto.keys.KeySendableData)
	 */
	@Override
	public PrivateKey reconstructPrivateKey(KeySendableData data) {
		if(! (data instanceof RSAPrivateKey))
			throw new IllegalArgumentException("To generate the key from sendable data, the data has to be of type RSAPrivateKey");
	return (RSAPrivateKey)data;
	}
	
	/* (non-Javadoc)
	 * @see edu.biu.scapi.midLayer.asymmetricCrypto.encryption.AsymmetricEnc#reconstructPublicKey(edu.biu.scapi.midLayer.asymmetricCrypto.keys.KeySendableData)
	 */
	@Override
	public PublicKey reconstructPublicKey(KeySendableData data) {
		if(! (data instanceof RSAPublicKey))
			throw new IllegalArgumentException("To generate the key from sendable data, the data has to be of type RSAPublicKey");
	return (RSAPublicKey)data;
	}

}
