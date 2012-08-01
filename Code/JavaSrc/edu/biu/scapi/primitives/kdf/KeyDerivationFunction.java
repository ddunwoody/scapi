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
	 * Generates a new secret key from the given seed.
	 * @param entropySource the secret key that is the seed for the key generation
	 * @param inOff the offset within the entropySource to take the bytes from
	 * @param inLen the length of the seed
	 * @param outLen the required output key length
	 * @return SecretKey the derivated key.
	 */
	public SecretKey derivateKey(byte[] entropySource, int inOff, int inLen, int outLen);
	
	/** 
	 * Generates a new secret key from the given seed and iv.
	 * @param entropySource the secret key that is the seed for the key generation
	 * @param inOff the offset within the entropySource to take the bytes from
	 * @param inLen the length of the seed
	 * @param outLen the required output key length
	 * @param iv info for the key generation
	 * @return SecretKey the derivated key.
	 */
	public SecretKey derivateKey(byte[] entropySource, int inOff, int inLen, int outLen, byte[] iv);
}