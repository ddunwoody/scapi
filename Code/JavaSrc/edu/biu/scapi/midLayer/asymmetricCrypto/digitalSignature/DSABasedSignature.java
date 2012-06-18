package edu.biu.scapi.midLayer.asymmetricCrypto.digitalSignature;

import edu.biu.scapi.securityLevel.ACMA;
import edu.biu.scapi.securityLevel.UnlimitedTimes;

/**
 * General interface for DSA signature scheme. Every concrete implementation of DSA signature should implement this interface.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public interface DSABasedSignature extends DigitalSignature, UnlimitedTimes, ACMA{

}
