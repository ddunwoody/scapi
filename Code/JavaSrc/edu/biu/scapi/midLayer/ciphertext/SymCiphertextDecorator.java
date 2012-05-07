package edu.biu.scapi.midLayer.ciphertext;
/**
 * The decorator pattern has been used to implement different types of symmetric ciphertext.<p>   
 * This abstract class is the decorator part of the pattern. It allows wrapping the base symmetric ciphertext with extra functionality.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
abstract class SymCiphertextDecorator implements SymmetricCiphertext {

	//The symmetric ciphertext we want to decorate.
	protected SymmetricCiphertext cipher;
	
	/**
	 * This constructor gets the symmetric ciphertext that we need to decorate.
	 * @param cipher
	 */
	public SymCiphertextDecorator(SymmetricCiphertext cipher){
		this.cipher = cipher;
	}
	
	/**
	 * 
	 * @return the undecorated cipher.
	 */
	public SymmetricCiphertext getCipher() {
		return this.cipher;
	}
	
	/*
	 * (non-Javadoc)
	 * @see edu.biu.scapi.midLayer.ciphertext.SymmetricCiphertext#getBytes()
	 * Delegate to underlying (decorated) ciphertext. This behavior can be overridden by inheriting classes.
	 */
	public byte[] getBytes(){
		return cipher.getBytes();
	}

	/*
	 * (non-Javadoc)
	 * @see edu.biu.scapi.midLayer.ciphertext.SymmetricCiphertext#getLength()
	 * Delegate to underlying (decorated) ciphertext. This behavior can be overridden by inheriting classes.
	 */
	@Override
	public int getLength() {
		return cipher.getLength();
	}
}
