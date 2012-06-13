package edu.biu.scapi.midLayer.asymmetricCrypto.encryption;

import edu.biu.scapi.securityLevel.*;

/**
 * General interface for CramerShoup encryption scheme. Every concrete implementation of CramerShoup encryption should implement this interface.
 * By definition, this encryption scheme is CCA-secure and NonMalleable.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public interface CramerShoupDDHEnc extends AsymmetricEnc, Cca2, NonMalleable {

}
