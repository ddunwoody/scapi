package edu.biu.scapi.primitives.hash.cryptopp;

import edu.biu.scapi.primitives.hash.SHA512;

/** 
 * Concrete class of cryptographicHash for SHA512. This class wraps crypto++ implementation of SHA512.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 */
public final class CryptoPpSHA512 extends CryptoPpHash implements SHA512 {

	/**
	 * Passes the hash name to the super class which does the hash computation
	 */
	public CryptoPpSHA512() {
		//calls the super constructor with the name of the hash - SHA512.
		super("SHA512");
	}

}
