/**
 * 
 */
package edu.biu.scapi.midLayer.ciphertext;

/**
 * This class is a container for cipher-texts that include actual cipher data and the IV used.
 * This is a concrete decorator in the Decorator Pattern used for Symmetric Ciphertext.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class IVCiphertext extends SymCiphertextDecorator {
	private byte[] iv;
	
	/**
	 * Constructs a container for Ciphertexts that need an IV. 
	 * @param cipher symmetric ciphertext to which we need to add an IV.
	 * @param iv the IV we need to add to the ciphertext.
	 */
	public IVCiphertext(SymmetricCiphertext cipher, byte[] iv){
		super(cipher);
		this.iv = iv;
	}
	
	/**
	 * 
	 * @return the IV of this ciphertext-with-IV.
	 */
	public byte[] getIv(){
		return iv;
	}	
	
}
