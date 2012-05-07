/**
 * 
 */
package edu.biu.scapi.midLayer.asymmetricCrypto.encryption;

import java.math.BigInteger;

import edu.biu.scapi.midLayer.ciphertext.Ciphertext;

/**
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public interface AsymAdditiveHomomorphicEnc extends AsymmetricEnc {
	/**
	 * Receives two ciphertexts and return their addition.
	 * @param cipher1
	 * @param cipher2
	 * @return the addition result
	 */
	public Ciphertext add(Ciphertext cipher1, Ciphertext cipher2);
	public Ciphertext multByConst(Ciphertext cipher1, BigInteger constNumber);
}
