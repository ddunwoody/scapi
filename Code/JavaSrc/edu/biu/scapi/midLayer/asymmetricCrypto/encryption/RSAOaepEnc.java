package edu.biu.scapi.midLayer.asymmetricCrypto.encryption;

import edu.biu.scapi.securityLevel.Cca2;
import edu.biu.scapi.securityLevel.NonMalleable;

/**
 * General interface for RSA OAEP encryption scheme. Every concrete implementation of RSA OAEP encryption should implement this interface.
 * By definition, this encryption scheme is CCA-secure and NonMalleable.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public interface RSAOaep extends AsymmetricEnc, Cca2, NonMalleable{

}
