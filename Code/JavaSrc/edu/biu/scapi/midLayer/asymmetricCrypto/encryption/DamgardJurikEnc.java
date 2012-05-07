/**
 * 
 */
package edu.biu.scapi.midLayer.asymmetricCrypto.encryption;

import edu.biu.scapi.midLayer.ciphertext.Ciphertext;

/**
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public interface DamgardJurikEnc extends AsymAdditiveHomomorphicEnc {
	public Ciphertext reRandomize(Ciphertext cipher);
}
