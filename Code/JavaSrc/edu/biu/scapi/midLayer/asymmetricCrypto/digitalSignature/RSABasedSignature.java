package edu.biu.scapi.midLayer.asymmetricCrypto.digitalSignature;

import edu.biu.scapi.securityLevel.ACMA;
import edu.biu.scapi.securityLevel.UnlimitedTimes;

/**
 * General interface for RSA PSS signature scheme. Every concrete implementation of RSA PSS signature should implement this interface.
 * The RSA PSS (Probabilistic Signature Scheme) is a provably secure way of creating signatures with RSA.
 *  
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public interface RSABasedSignature extends DigitalSignature, UnlimitedTimes, ACMA{

}
