package edu.biu.scapi.primitives.hash.cryptopp;

import edu.biu.scapi.primitives.hash.SHA1;

/** 
 * Concrete class of cryptographicHash for SHA1. This class wraps crypto++ implementation of SHA1.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 */
public final class CryptoPpSHA1 extends CryptoPpHash implements SHA1 {

	/**
	 * Passes the hash name to the super class which does the hash computation
	 */
	public CryptoPpSHA1() {
		//calls the super constructor with the name of the hash - SHA1.
		super("SHA1");
	}


}
