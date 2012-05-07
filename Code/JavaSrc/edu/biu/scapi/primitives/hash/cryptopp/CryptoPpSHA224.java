package edu.biu.scapi.primitives.hash.cryptopp;

import edu.biu.scapi.primitives.hash.SHA224;

/** 
 * Concrete class of cryptographicHash for SHA224. This class wraps crypto++ implementation of SHA224.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 */
public final class CryptoPpSHA224 extends CryptoPpHash implements SHA224 {

	
	/**
	 * Passes the hash name to the super class which does the hash computation
	 */
	public CryptoPpSHA224() {
		//calls the super constructor with the name of the hash - SHA224.
		super("SHA224");
	}

}
