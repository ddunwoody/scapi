package edu.biu.scapi.midLayer.asymmetricCrypto.encryption;

import edu.biu.scapi.midLayer.ciphertext.Ciphertext;

/**
 * General interface for DamgardJurik encryption scheme. Every concrete implementation of DamgardJurik encryption should implement this interface.
 * By definition, this encryption scheme is CPA-secure and Indistinguishable.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public interface DamgardJurikEnc extends AsymAdditiveHomomorphicEnc {
	
	/**
	 * This function takes an encryption of some plaintext (let's call it originalPlaintext) and returns a cipher that "looks" different but
	 * it is also an encryption of originalPlaintext.<p>
	 * @param cipher
	 * @throws IllegalArgumentException if the given ciphertext does not match this asymmetric encryption.
	 */
	public Ciphertext reRandomize(Ciphertext cipher);
}
