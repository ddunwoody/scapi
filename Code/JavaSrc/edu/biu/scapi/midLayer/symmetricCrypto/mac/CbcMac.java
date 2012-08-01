package edu.biu.scapi.midLayer.symmetricCrypto.mac;

import edu.biu.scapi.primitives.prf.PrfVaryingInputLength;

/**
 * General interface for CBC-Mac. every class that implement the cbc-mac algorithm should implement this interface.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public interface CbcMac extends UniqueTagMac, PrfVaryingInputLength{

	/**
	 * Pre-pends the length if the message to the message.
	 * As a result, the mac will be calculated on [msgLength||msg].
	 * @param msgLength the length of the message in bytes.
	 */
	public void startMac(int msgLength);
}
