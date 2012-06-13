package edu.biu.scapi.midLayer.plaintext;

/**
 * This class holds the plaintext as a ByteArray.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class ByteArrayPlaintext implements Plaintext {
	private byte[] text = null;
	
	public ByteArrayPlaintext (byte[] text) {
		this.text = text;
	}
	
	public byte[] getText() {
		return text;
	}
	
	@Override
	public boolean equals(Object plaintext){
		if (!(plaintext instanceof ByteArrayPlaintext)){
			return false;
		}
		byte[] text2 = ((ByteArrayPlaintext) plaintext).getText();
		
		if (text.length != text2.length){
			return false;
		}
		
		for (int i=0; i<text.length; i++){
			if (text[i] != text2[i]){
				return false;
			}
		}
		
		return true;
	}
}
