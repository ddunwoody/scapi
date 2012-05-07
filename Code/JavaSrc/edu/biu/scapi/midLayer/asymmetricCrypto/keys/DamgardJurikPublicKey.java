/**
 * 
 */
package edu.biu.scapi.midLayer.asymmetricCrypto.keys;

import java.math.BigInteger;
import java.security.PublicKey;

/**
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public interface DamgardJurikPublicKey extends PublicKey {

	BigInteger getModulus();
}
