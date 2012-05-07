package edu.biu.scapi.primitives.kdf;

import javax.crypto.SecretKey;

/** 
 * General interface of key derivation function. Every class in this family should implement this interface. <p>
 * A key derivation function (or KDF) is used to derive (close to) uniformly distributed string/s from a secret value 
 * with high entropy (but no other guarantee regarding its distribution). 
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 */
public interface KeyDerivationFunction {
	
	/** 
	 * Generates a new secret key from the given seed and IV.
	 * @param seedForGeneration the secret key that is the seed for the key generation
	 * @param len the required output key length
	 * @param iv info for the key generation
	 * @return secret key the generated key
	 */
	public SecretKey generateKey(SecretKey seedForGeneration, int outLen,  byte[] iv) ;
	
	/** 
	 * Generates a new secret key from the given seed.
	 * @param seedForGeneration the secret key that is the seed for the key generation
	 * @param len the required output key length
	 * @return secret key the generated key
	 */
	public SecretKey generateKey(SecretKey seedForGeneration, int outLen) ;
	
	/** 
	 * Generates a new secret key from the given seed.
	 * @param seedForGeneration the secret key that is the seed for the key generation
	 * @param inOff the offset within the seedForGeneration to take the bytes from
	 * @param inLen the length of the seed
	 * @param outKey the array to put the generated key bytes
	 * @param outoff the offset within the output array to put the generated key bytes from
	 * @param outlen the required output key length
	 */
	public void generateKey(byte[] seedForGeneration, int inOff, int inLen, byte[] outKey, int outOff, int outLen) ;
	
	/** 
	 * Generates a new secret key from the given seed and iv.
	 * @param seedForGeneration the secret key that is the seed for the key generation
	 * @param inOff the offset within the seedForGeneration to take the bytes from
	 * @param inLen the length of the seed
	 * @param outKey the array to put the generated key bytes
	 * @param outoff the offset within the output array to put the generated key bytes from
	 * @param outlen the required output key length
	 * @param iv info for the key generation
	 */
	public void generateKey(byte[] seedForGeneration, int inOff, int inLen, byte[] outKey, int outOff, int outLen, byte[] iv) ;
}