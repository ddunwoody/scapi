package edu.biu.scapi.midLayer.asymmetricCrypto.encryption;

import java.math.BigInteger;

import edu.biu.scapi.midLayer.ciphertext.Ciphertext;

/**
 * General interface for asymmetric additive homomorphic encryption.
 * Such encryption schemes can compute the encryption of m1+m2, given only the public key and the encryptions of m1 and m2.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public interface AsymAdditiveHomomorphicEnc extends AsymmetricEnc {
	/**
	 * Receives two ciphertexts and return their addition.
	 * @param cipher1
	 * @param cipher2
	 * @return the addition result
	 * @throws IllegalStateException if no public key was set.
	 * @throws IllegalArgumentException if the given ciphertexts do not match this asymmetric encryption.
	 */
	public Ciphertext add(Ciphertext cipher1, Ciphertext cipher2);
	
	/**
	 * Receives a cipher and a constant number and returns their multiplication.
	 * @param cipher
	 * @param constNumber
	 * @return the multiplication result.
	 * @throws IllegalStateException if no public key was set.
	 * @throws IllegalArgumentException if the given ciphertext does not match this asymmetric encryption.
	 */
	public Ciphertext multByConst(Ciphertext cipher, BigInteger constNumber);
}
