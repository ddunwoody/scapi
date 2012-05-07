package edu.biu.scapi.midLayer.asymmetricCrypto.encryption;

import edu.biu.scapi.midLayer.ciphertext.Ciphertext;

/**
 * Interface for asymmetric multiplicative homomorphic encryption.
 *  
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public interface AsymMultiplicativeHomomorphicEnc extends AsymmetricEnc{

	/**
	 * Multiplies two ciphertexts and return their multiplication
	 * @param cipher1
	 * @param cipher2
	 * @return the multiplication result
	 */
	public Ciphertext multiply(Ciphertext cipher1, Ciphertext cipher2);
}
