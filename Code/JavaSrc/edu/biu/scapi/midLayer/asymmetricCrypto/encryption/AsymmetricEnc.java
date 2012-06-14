package edu.biu.scapi.midLayer.asymmetricCrypto.encryption;

import java.security.InvalidKeyException;
import java.security.KeyException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import edu.biu.scapi.midLayer.ciphertext.Ciphertext;
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
	 * Returns the PublicKey of this encryption scheme.
	 * @return the PublicKey
	 * @throws IllegalStateException if no public key was set.
	 */
	public PublicKey getPublicKey();
	
		
	/**
	 * @return the name of this AsymmetricEnc
	 */
	public String getAlgorithmName();
	
	/**
	 * Encrypts the given plaintext using this asymmetric encryption scheme.
	 * @param plaintext message to encrypt
	 * @return Ciphertext the encrypted plaintext
	 * @throws IllegalArgumentException if the given Plaintext doesn't match this encryption type.
	 * @throws IllegalStateException if no public key was set.
	 */
	public Ciphertext encrypt(Plaintext plainText);
	
	/**
	 * Decrypts the given ciphertext using this asymmetric encryption scheme.
	 * @param cipher ciphertext to decrypt
	 * @return Plaintext the decrypted cipher
	 * @throws KeyException if there is no private key
	 * @throws IllegalArgumentException if the given Ciphertext doesn't march this encryption type.
	 */
	public Plaintext decrypt(Ciphertext cipher) throws KeyException;
	
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
