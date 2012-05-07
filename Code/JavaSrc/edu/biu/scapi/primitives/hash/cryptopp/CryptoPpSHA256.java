package edu.biu.scapi.primitives.hash.cryptopp;

import edu.biu.scapi.primitives.hash.SHA256;

/** 
 * Concrete class of cryptographicHash for SHA256. This class wraps crypto++ implementation of SHA256.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 */
public final class CryptoPpSHA256 extends CryptoPpHash implements SHA256 {

	/**
	 * Passes the hash name to the super class which does the hash computation
	 */
	public CryptoPpSHA256() {
		//calls the super constructor with the name of the hash - SHA256.
		super("SHA256");
	}

}
