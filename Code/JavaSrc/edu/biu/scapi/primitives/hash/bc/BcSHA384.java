package edu.biu.scapi.primitives.hash.bc;

import org.bouncycastle.crypto.digests.SHA384Digest;

import edu.biu.scapi.primitives.hash.SHA384;

/** 
 * Concrete class of cryptographicHash for SHA384. This class wraps BouncyCastle implementation of SHA384.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 */
public final class BcSHA384 extends BcHash implements SHA384 {

	/**
	 * Passes the digest SHA384 of BC to the super class which does the hash computation. 
	 */
	public BcSHA384() {
		//passes the digest SHA384 of BC. 
		super(new SHA384Digest());
	}
}
