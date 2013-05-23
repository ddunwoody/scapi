package edu.biu.scapi.midLayer.ciphertext;

import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.dlog.GroupElementSendableData;

public class ElGamalKEMCiphertext implements AsymmetricCiphertext{

	
	//First part of the ciphertext.
	private GroupElement u;
	//Second part of the ciphertext.
	private SymmetricCiphertext w;
	
	/**
	 * Create an instance of this container class.
	 * This constructor is used by the Encryption Scheme as a result of a call to function encrypt. 
	 * @param c1 the first part of the cihertext
	 * @param c2 the second part of the ciphertext
	 */
	public ElGamalKEMCiphertext(GroupElement u, SymmetricCiphertext w){
		this.u = u;
		this.w = w;
	}

	/**
	 * 
	 * @return the first part of the ciphertext
	 */
	public GroupElement getU(){
		return u;
	}
	
	/**
	 * 
	 * @return the second part of the ciphertext
	 */
	public SymmetricCiphertext getW(){
		return w;
	}
	
	/**
	 * @see edu.biu.scapi.midLayer.ciphertext.AsymmetricCiphertext#generateSendableData()
	 */
	@Override
	public AsymmetricCiphertextSendableData generateSendableData() {
		return new ElGamalKEMSendableData(u.generateSendableData(), w);
	}
	
	@Override
	public String toString() {
		return "ElGamalKEMCiphertext [u=" + u
				+ ", w=" + w + "]";
	}
	
	
	//Nested class that holds the sendable data of the outer class
	static public class ElGamalKEMSendableData implements AsymmetricCiphertextSendableData {

		
		private static final long serialVersionUID = -2948506522397684981L;
		
		//First part of the ciphertext.
		private GroupElementSendableData u;
		//Second part of the ciphertext.
		private SymmetricCiphertext w;
		
		public ElGamalKEMSendableData(GroupElementSendableData u,
				SymmetricCiphertext w) {
			super();
			this.u = u;
			this.w = w;
		}
		public GroupElementSendableData getU() {
			return u;
		}
		public SymmetricCiphertext getW() {
			return w;
		}



	}

}
