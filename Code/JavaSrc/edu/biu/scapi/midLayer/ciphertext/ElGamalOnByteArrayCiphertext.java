package edu.biu.scapi.midLayer.ciphertext;

import edu.biu.scapi.primitives.dlog.GroupElement;

public class ElGamalOnByteArrayCiphertext implements AsymmetricCiphertext{

	//First part of the ciphertext.
	private GroupElement cipher1;
	//Second part of the ciphertext.
	private byte[] cipher2;
	
	/**
	 * Create an instance of this container class 
	 * @param c1 the first part of the cihertext
	 * @param c2 the second part of the ciphertext
	 */
	public ElGamalOnByteArrayCiphertext(GroupElement c1, byte[] c2){
		this.cipher1 = c1;
		this.cipher2 = c2;
	}
	
	/**
	 * 
	 * @return the first part of the ciphertext
	 */
	public GroupElement getC1(){
		return cipher1;
	}
	
	/**
	 * 
	 * @return the second part of the ciphertext
	 */
	public byte[] getC2(){
		return cipher2;
	}
}
