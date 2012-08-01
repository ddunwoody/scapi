package edu.biu.scapi.midLayer.ciphertext;

public class ByteArrayAsymCiphertext implements AsymmetricCiphertext {

	byte[] data = null;
	
	
	/**
	 * The encrypted bytes need to be passed to construct this holder.
	 * @param data
	 */
	public ByteArrayAsymCiphertext(byte[] data) {
		this.data = data;
	}

	
	public byte[] getBytes() {
		return data;
	}

	public int getLength() {
		return data.length;
	}
}
