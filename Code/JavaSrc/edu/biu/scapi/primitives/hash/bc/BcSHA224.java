package edu.biu.scapi.primitives.hash.bc;

import org.bouncycastle.crypto.digests.SHA224Digest;

import edu.biu.scapi.primitives.hash.SHA224;

/** 
 * Concrete class of cryptographicHash for SHA224. This class wraps BouncyCastle implementation of SHA224.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 */
public final class BcSHA224 extends BcHash implements SHA224 {

	/** 
	 * Passes the digest SHA224 of BC to the super class which does the hash computation. 
	 */
	public BcSHA224() {
		//passes the digest SHA224 of BC. 
		super(new SHA224Digest());
	}
}
