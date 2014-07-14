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
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import edu.biu.scapi.exceptions.NoMaxException;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.KeySendableData;
import edu.biu.scapi.midLayer.ciphertext.AsymmetricCiphertext;
import edu.biu.scapi.midLayer.ciphertext.AsymmetricCiphertextSendableData;
import edu.biu.scapi.midLayer.plaintext.Plaintext;
import edu.biu.scapi.securityLevel.Cpa;
import edu.biu.scapi.securityLevel.Indistinguishable;

/**
 * General interface for asymmetric encryption. Each class of this family must implement this interface. <p>
 * 
 * Asymmetric encryption refers to a cryptographic system requiring two separate keys, one to encrypt the plaintext, and one to decrypt the ciphertext. 
 * Neither key will do both functions. 
 * One of these keys is public and the other is kept private. 
 * If the encryption key is the one published then the system enables private communication from the public to the decryption key's owner.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public interface AsymmetricEnc extends Cpa, Indistinguishable{

	/**
	 * Sets this asymmetric encryption with public key and private key.
	 * @param publicKey
	 * @param privateKey
	 * @throws InvalidKeyException if the given keys don't match this encryption scheme.
	 */
	public void setKey(PublicKey publicKey, PrivateKey privateKey)throws InvalidKeyException;
	
	/**
	 * Sets this asymmetric encryption with a public key<p> 
	 * In this case the encryption object can be used only for encryption.
	 * @param publicKey
	 * @throws InvalidKeyException if the given key doesn't match this encryption scheme.
	 */
	public void setKey(PublicKey publicKey)throws InvalidKeyException;
	
	/**
	 * Checks if this AsymmetricEnc object has been previously initialized with corresponding keys.<p> 
	 * @return <code>true</code> if either the Public Key has been set or the key pair (Public Key, Private Key) has been set;<P>
	 * 		   <code>false</code> otherwise.
	 */
	public boolean isKeySet();
	
	/**
	 * Returns the PublicKey of this encryption scheme. <p>
	 * This function should not be use to check if the key has been set. 
	 * To check if the key has been set use isKeySet function.
	 * @return the PublicKey
	 * @throws IllegalStateException if no public key was set.
	 */
	public PublicKey getPublicKey();
	
		
	/**
	 * @return the name of this AsymmetricEnc
	 */
	public String getAlgorithmName();
	
	/**
	 * There are some encryption schemes that have a limit of the byte array that can be passed to the generatePlaintext.
	 * This function indicates whether or not there is a limit. 
	 * Its helps the user know if he needs to pass an array with specific length or not.
	 * @return true if this encryption scheme has a maximum byte array length to generate a plaintext from; false, otherwise. 
	 */
	public boolean hasMaxByteArrayLengthForPlaintext();
	
	/**
	 * Returns the maximum size of the byte array that can be passed to generatePlaintext function. 
	 * This is the maximum size of a byte array that can be converted to a Plaintext object suitable to this encryption scheme.
	 * @return the maximum size of the byte array that can be passed to generatePlaintext function. 
	 * @throws NoMaxException if this encryption scheme has no limit on the plaintext input.
	 */
	public int getMaxLengthOfByteArrayForPlaintext() throws NoMaxException;
	
	/**
	 * Generates a Plaintext suitable for this encryption scheme from the given message.<p>
	 * A Plaintext object is needed in order to use the encrypt function. Each encryption scheme might generate a different type of Plaintext
	 * according to what it needs for encryption. The encryption function receives as argument an object of type Plaintext in order to allow a protocol
	 * holding the encryption scheme to be oblivious to the exact type of data that needs to be passed for encryption.  
	 * @param text byte array to convert to a Plaintext object.
	 * @throws IllegalArgumentException if the given message's length is greater than the maximum. 
	 */
	public Plaintext generatePlaintext(byte[] text);
	
	
	/**
	 * Generates (reconstructs) a suitable AsymmetricCiphertext from data that was probably obtained via a Channel or any other means of sending data (including serialization).<p>
	 * We emphasize that this is NOT in any way an encryption function, it just receives ENCRYPTED DATA and places it in a ciphertext object. 
	 * @param data contains all the necessary information to construct a suitable ciphertext.  
	 * @return the AsymmetricCiphertext that corresponds to the implementing encryption scheme, for ex: CramerShoupCiphertext
	 * @deprecated As of SCAPI-V1-0-2-2 use reconstructCiphertext(AsymmetricCiphertextSendableData data)
	 */
	@Deprecated public AsymmetricCiphertext generateCiphertext(AsymmetricCiphertextSendableData data);
	
	/**
	 * Reconstructs a suitable AsymmetricCiphertext from data that was probably obtained via a Channel or any other means of sending data (including serialization).<p>
	 * We emphasize that this is NOT in any way an encryption function, it just receives ENCRYPTED DATA and places it in a ciphertext object. 
	 * @param data contains all the necessary information to construct a suitable ciphertext.  
	 * @return the AsymmetricCiphertext that corresponds to the implementing encryption scheme, for ex: CramerShoupCiphertext
	 */
	public AsymmetricCiphertext reconstructCiphertext(AsymmetricCiphertextSendableData data);

	/**
	 * Encrypts the given plaintext using this asymmetric encryption scheme.
	 * @param plainText message to encrypt
	 * @return Ciphertext the encrypted plaintext
	 * @throws IllegalArgumentException if the given Plaintext doesn't match this encryption type.
	 * @throws IllegalStateException if no public key was set.
	 */
	public AsymmetricCiphertext encrypt(Plaintext plainText);
	
	/**
	 * Encrypts the given plaintext using this asymmetric encryption scheme and using the given random value.<p>
	 * There are cases when the random value is used after the encryption, for example, in sigma protocol. 
	 * In these cases the random value should be known to the user. We decided not to have function that return it to the user 
	 * since this can cause problems when more than one value is being encrypt. 
	 * Instead, we decided to have an additional encrypt function that gets the random value from the user.
	 * @param plainText message to encrypt
	 * @param r The random value to use in the encryption. 
	 * @return Ciphertext the encrypted plaintext
	 * @throws IllegalArgumentException if the given Plaintext doesn't match this encryption type.
	 * @throws IllegalStateException if no public key was set.
	 */
	public AsymmetricCiphertext encrypt(Plaintext plainText, BigInteger r);
	
	/**
	 * Decrypts the given ciphertext using this asymmetric encryption scheme.
	 * @param cipher ciphertext to decrypt
	 * @return Plaintext the decrypted cipher
	 * @throws KeyException if there is no private key
	 * @throws IllegalArgumentException if the given Ciphertext doesn't march this encryption type.
	 */
	public Plaintext decrypt(AsymmetricCiphertext cipher) throws KeyException;
	
	/**
	 * Generates a byte array from the given plaintext. 
	 * This function should be used when the user does not know the specific type of the Asymmetric encryption he has, 
	 * and therefore he is working on byte array.
	 * @param plaintext to generates byte array from.
	 * @return the byte array generated from the given plaintext.
	 */
	public byte[] generateBytesFromPlaintext(Plaintext plaintext);
	
	/**
	 * Generates public and private keys for this asymmetric encryption.
	 * @param keyParams hold the required parameters to generate the encryption scheme's keys
	 * @return KeyPair holding the public and private keys relevant to the encryption scheme
	 * @throws InvalidParameterSpecException if the given parameters don't match this encryption scheme.
	 */
	public KeyPair generateKey(AlgorithmParameterSpec keyParams) throws InvalidParameterSpecException;
	
	/**
	 * Generates public and private keys for this asymmetric encryption.
	 * @return KeyPair holding the public and private keys
	 */
	public KeyPair generateKey();
	
	/**
 	 * Reconstructs a suitable PublicKey from data that was probably obtained via a Channel or any other means of sending data (including serialization).<p>
	 * We emphasize that this function does NOT in any way generate a key, it just receives data and recreates a PublicKey object. 
 	 * @param data a KeySendableData object needed to recreate the original key. The actual type of KeySendableData has to be suitable to the actual encryption scheme used, otherwise it throws an IllegalArgumentException
	 * @return a new PublicKey with the data obtained as argument  
	 */
	public PublicKey reconstructPublicKey(KeySendableData data);
	
	/**
 	 * Reconstructs a suitable PrivateKey from data that was probably obtained via a Channel or any other means of sending data (including serialization).<p>
	 * We emphasize that this function does NOT in any way generate a key, it just receives data and recreates a PrivateKey object. 
 	 * @param data a KeySendableData object needed to recreate the original key. The actual type of KeySendableData has to be suitable to the actual encryption scheme used, otherwise it throws an IllegalArgumentException
	 * @return a new PrivateKey with the data obtained as argument  
	 */
	public PrivateKey reconstructPrivateKey(KeySendableData data);
		
}
