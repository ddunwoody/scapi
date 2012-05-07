package edu.biu.scapi.primitives.hash;


/**
 * General interface for CryptographicHash. Every concrete class should implement this interface. <p>
 * 
 * A cryptographic hash function is a deterministic procedure that takes an arbitrary block of data and returns a fixed-size bit string, 
 * the (cryptographic) hash value. 
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 */
public interface CryptographicHash {

	/** 
	 * @return The algorithm name. For example - SHA1
	 */
	public String getAlgorithmName();

	/** 
	 * @return the size of the hashed massage in bytes
	 */
	public int getHashedMsgSize();

	/**
	 * Adds the byte array to the existing message to hash. 
	 * @param in input byte array
	 * @param inOffset the offset within the byte array
	 * @param inLen the length. The number of bytes to take after the offset
	 * */
	public void update(byte[] in, int inOffset, int inLen);

	/** 
	 * Completes the hash computation and puts the result in the out array.
	 * @param out the output in byte array
	 * @param outOffset the offset which to put the result bytes from
	 */
	public void hashFinal(byte[] out, int outOffset);
}