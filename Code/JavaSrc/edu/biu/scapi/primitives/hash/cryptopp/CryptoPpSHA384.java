package edu.biu.scapi.primitives.hash.cryptopp;

import edu.biu.scapi.primitives.hash.SHA384;

/** 
 * Concrete class of cryptographicHash for SHA384. This class wraps crypto++ implementation of SHA384.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 */
public final class CryptoPpSHA384 extends CryptoPpHash implements SHA384 {

	/**
	 * Passes the hash name to the super class which does the hash computation
	 */
	public CryptoPpSHA384() {
		//calls the super constructor with the name of the hash - SHA384.
		super("SHA384");
	}

}
