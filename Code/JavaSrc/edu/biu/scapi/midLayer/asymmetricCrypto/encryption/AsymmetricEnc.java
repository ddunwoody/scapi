/**
* This file is part of SCAPI.
* SCAPI is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
* SCAPI is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
* You should have received a copy of the GNU General Public License along with SCAPI.  If not, see <http://www.gnu.org/licenses/>.
*
* Any publication and/or code referring to and/or based on SCAPI must contain an appropriate citation to SCAPI, including a reference to http://crypto.cs.biu.ac.il/SCAPI.
*
* SCAPI uses Crypto++, Miracl, NTL and Bouncy Castle. Please see these projects for any further licensing issues.
*
*/
package edu.biu.scapi.midLayer.asymmetricCrypto.encryption;

import java.security.InvalidKeyException;
import java.security.KeyException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import edu.biu.scapi.exceptions.NoMaxException;
import edu.biu.scapi.midLayer.ciphertext.AsymmetricCiphertext;
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
	 * @return <code>true<code> if either the Public Key has been set or the key pair (Public Key, Private Key) has been set;<P>
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
	 * There are some encryption schemes that have a limit of the byte array that can be passes to the generatePlaintext.
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
	 * Generates a Plaintext suitable to this encryption scheme from the given message.
	 * @param text byte array to convert to a Plaintext object.
	 * @throws IllegalArgumentException if the given message's length is greater than the maximum. 
	 */
	public Plaintext generatePlaintext(byte[] text);
	
	/**
	 * Encrypts the given plaintext using this asymmetric encryption scheme.
	 * @param plainText message to encrypt
	 * @return Ciphertext the encrypted plaintext
	 * @throws IllegalArgumentException if the given Plaintext doesn't match this encryption type.
	 * @throws IllegalStateException if no public key was set.
	 */
	public AsymmetricCiphertext encrypt(Plaintext plainText);
	
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
		
}
