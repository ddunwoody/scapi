/**
 * 
 */
package edu.biu.scapi.midLayer.asymmetricCrypto.keys;

import java.math.BigInteger;
import java.security.PrivateKey;

/**
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public interface DamgardJurikPrivateKey extends PrivateKey {

	BigInteger getT();

	BigInteger getDForS1();
}
