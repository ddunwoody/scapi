package edu.biu.scapi.primitives.hash.bc;

import org.bouncycastle.crypto.Digest;

import edu.biu.scapi.primitives.hash.CryptographicHash;

/** 
 * A general adapter class of hash for Bouncy Castle. <p>
 * This class implements all the functionality by passing requests to the adaptee interface Digest. 
 * A concrete hash function such as SHA1 represented by the class BcSHA1 only passes the SHA1Digest object in the constructor 
 * to the base class. 
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 * 
 */
public abstract class BcHash implements CryptographicHash {
	private Digest digest; //the underlying digest
	
	 /**
	  * Sets the underlying digest
	  * @param digest the underlying digest of BC
	  */
	public BcHash(Digest digest) {
	
		//sets the underlying bc digest
		this.digest = digest;
	}
	
	/** 
	 * @return the algorithm name taken from BC
	 */
	public String getAlgorithmName() {
	
		//gets the name from the digest of BC
		return digest.getAlgorithmName();
	}

	/**
	 * @return the size of the hashed message in bytes
	 */
	public int getHashedMsgSize() {
		
		//gets the size from the underlying digest
		return digest.getDigestSize();
	}

	/**
	 * Adds the byte array to the existing message to hash. 
	 * @param in input byte array
	 * @param inOffset the offset within the byte array
	 * @param inLen the length. The number of bytes to take after the offset
	 * */
	public void update(byte[] in, int inOffset, int inLen) {
		
		//checks that the offset and length are correct
		if ((inOffset > in.length) || (inOffset+inLen > in.length)){
			throw new ArrayIndexOutOfBoundsException("wrong offset for the given input buffer");
		}
		//delegates the update request to the underlying digest
		digest.update(in, inOffset, inLen);
	}

	/** 
	 * Completes the hash computation and puts the result in the out array.
	 * @param out the output in byte array
	 * @param outOffset the offset which to put the result bytes from
	 */
	public void hashFinal(byte[] out, int outOffset) {
		
		//checks that the offset and length are correct
		if ((outOffset > out.length) || (outOffset+getHashedMsgSize() > out.length)){
			throw new ArrayIndexOutOfBoundsException("wrong offset for the given output buffer");
		}
		//delegates the update request to the underlying digest by calling it's function doFinal. This function
		//will update the out array.
		digest.doFinal(out, outOffset);
	}
}