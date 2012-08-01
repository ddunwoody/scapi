package edu.biu.scapi.midLayer.symmetricCrypto.encryption;

import edu.biu.scapi.securityLevel.Cca2;
import edu.biu.scapi.securityLevel.NonMalleable;

/**
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public interface AuthenticatedEnc extends SymmetricEnc, Cca2, NonMalleable {

}
