/**
 * 
 */
package edu.biu.scapi.midLayer.ciphertext;

/**
 * General interface for any symmetric ciphertext.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public interface SymmetricCiphertext extends Ciphertext {
	/**
	 * @return the byte array representation of the ciphertext.
	 */
	public byte[] getBytes();
	
	/**
	 * @return the length of the byte array representation of the ciphertext.
	 */
	public int getLength();
}
