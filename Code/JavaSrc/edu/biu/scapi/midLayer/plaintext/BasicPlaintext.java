/**
 * 
 */
package edu.biu.scapi.midLayer.plaintext;

/**
 * This class holds the basic data of any plain-text.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class BasicPlaintext implements Plaintext {
	private byte[] text = null;
	
	public BasicPlaintext (byte[] text) {
		this.text = text;
	}
	
	public byte[] getText() {
		return text;
	}
}
