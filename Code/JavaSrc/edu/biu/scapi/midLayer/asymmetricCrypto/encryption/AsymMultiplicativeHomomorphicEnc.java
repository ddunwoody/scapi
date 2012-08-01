package edu.biu.scapi.midLayer.asymmetricCrypto.encryption;

import edu.biu.scapi.midLayer.ciphertext.AsymmetricCiphertext;

/**
 * Interface for asymmetric multiplicative homomorphic encryption.
 * Such encryption schemes can compute the encryption of m1*m2, given only the public key and the encryptions of m1 and m2.
 *  
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public interface AsymMultiplicativeHomomorphicEnc extends AsymmetricEnc{

	/**
	 * Receives two ciphertexts and return their multiplication
	 * @param cipher1
	 * @param cipher2
	 * @return the multiplication result
	 * @throws IllegalStateException if no public key was set.
	 * @throws IllegalArgumentException if the given ciphertexts do not match this asymmetric encryption.
	 */
	public AsymmetricCiphertext multiply(AsymmetricCiphertext cipher1, AsymmetricCiphertext cipher2);
}
