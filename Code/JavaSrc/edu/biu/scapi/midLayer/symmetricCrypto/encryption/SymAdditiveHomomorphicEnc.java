package edu.biu.scapi.midLayer.symmetricCrypto.encryption;

import edu.biu.scapi.midLayer.ciphertext.SymmetricCiphertext;

/**
 * General interface for symmetric additive homomorphic encryption.
 * Such encryption scheme can compute the encryption of m1+m2, given only the encryptions of m1 and m2.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public interface SymAdditiveHomomorphicEnc extends SymmetricEnc {
	
	/**
	 * Given two ciphers c1 = enc(p1), c2 = enc(p2) this function returns c1 + c2 = enc(p1 + p2)
	 * @param c1 the encryption of p1
	 * @param c2 the encryption of p2
	 * @return the addition of c1 and c2.
	 */
	public SymmetricCiphertext add(SymmetricCiphertext c1, SymmetricCiphertext c2);

}
