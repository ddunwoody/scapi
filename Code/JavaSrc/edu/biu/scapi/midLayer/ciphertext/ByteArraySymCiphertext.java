package edu.biu.scapi.midLayer.ciphertext;

/**
 * This class represents the most basic symmetric ciphertext.
 * It is a data holder for the ciphertext calculated by some symmetric encryption algorithm. <p>
 * It only holds the actual "ciphered" bytes and not any additional information like for example in El Gamal encryption.
 *  
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 */
public class ByteArraySymCiphertext implements SymmetricCiphertext {

	byte[] data = null;
	
	
	/**
	 * The encrypted bytes need to be passed to construct this holder.
	 * @param data
	 */
	public ByteArraySymCiphertext(byte[] data) {
		this.data = data;
	}

	@Override
	public byte[] getBytes() {
		return data;
	}

	@Override
	public int getLength() {
		return data.length;
	}

	

}
