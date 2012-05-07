/**
 * 
 */
package edu.biu.scapi.midLayer.ciphertext;

/**
 * This class is a container for cipher-texts that include actual encrypted data and the resulting tag.
 * This is a concrete decorator in the Decorator Pattern used for Symmetric Ciphertext.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class EncMacCiphertext extends SymCiphertextDecorator {
	
	//The MAC tag.
	byte[] tag;

	/**
	 * Constructs a container for Encryption and Authentication Ciphertext. 
	 * @param cipher symmetric ciphertext to which we need to add a MAC-tag.
	 * @param tag the MAC-tag we need to add to the ciphertext.
	 */
	public EncMacCiphertext(SymmetricCiphertext cipher, byte[] tag){
		super(cipher);
		this.tag = tag;
	}
	
	/**
	 * 
	 * @return the MAC-tag of this authenticated ciphertext.
	 */
	public byte[] getTag() {
		return tag;
	}
	
}
