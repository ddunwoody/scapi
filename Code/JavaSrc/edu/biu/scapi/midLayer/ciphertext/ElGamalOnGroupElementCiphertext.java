/**
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
* Copyright (c) 2012 - SCAPI (http://crypto.biu.ac.il/scapi)
* This file is part of the SCAPI project.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
* 
* Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"),
* to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
* and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
* 
* The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
* 
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
* FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
* WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
* 
* We request that any publication and/or code referring to and/or based on SCAPI contain an appropriate citation to SCAPI, including a reference to
* http://crypto.biu.ac.il/SCAPI.
* 
* SCAPI uses Crypto++, Miracl, NTL and Bouncy Castle. Please see these projects for any further licensing issues.
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
*/


package edu.biu.scapi.midLayer.ciphertext;

import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.dlog.GroupElementSendableData;

/**
 * This class is a container that encapsulates the cipher data resulting from applying the ElGamalOnGroupElement encryption.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class ElGamalOnGroupElementCiphertext implements AsymmetricCiphertext {
	//First part of the ciphertext.
	private GroupElement cipher1;
	//Second part of the ciphertext.
	private GroupElement cipher2;
	
	/**
	 * Create an instance of this container class.
	 * This constructor is used by the Encryption Scheme as a result of a call to function encrypt. 
	 * @param c1 the first part of the cihertext
	 * @param c2 the second part of the ciphertext
	 */
	public ElGamalOnGroupElementCiphertext(GroupElement c1, GroupElement c2){
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
	public GroupElement getC2(){
		return cipher2;
	}

	/**
	 * @see edu.biu.scapi.midLayer.ciphertext.AsymmetricCiphertext#generateSendableData()
	 */
	@Override
	public AsymmetricCiphertextSendableData generateSendableData() {
		return new ElGamalOnGrElSendableData(cipher1.generateSendableData(), cipher2.generateSendableData());
	}
	
	
	
	
	@Override
	public String toString() {
		return "ElGamalOnGroupElementCiphertext [cipher1=" + cipher1
				+ ", cipher2=" + cipher2 + "]";
	}



	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		ElGamalOnGroupElementCiphertext other = (ElGamalOnGroupElementCiphertext) obj;
		if (cipher1 == null) {
			if (other.cipher1 != null)
				return false;
		} else if (!cipher1.equals(other.cipher1))
			return false;
		if (cipher2 == null) {
			if (other.cipher2 != null)
				return false;
		} else if (!cipher2.equals(other.cipher2))
			return false;
		return true;
	}




	//Nested class that holds the sendable data of the outer class
	static public class ElGamalOnGrElSendableData implements ElGamalCiphertextSendableData {

		private static final long serialVersionUID = 4480691511084748707L;

		GroupElementSendableData cipher1;
		GroupElementSendableData cipher2;
		public ElGamalOnGrElSendableData(GroupElementSendableData cipher1,
				GroupElementSendableData cipher2) {
			super();
			this.cipher1 = cipher1;
			this.cipher2 = cipher2;
		}
		public GroupElementSendableData getCipher1() {
			return cipher1;
		}
		public GroupElementSendableData getCipher2() {
			return cipher2;
		}
		
		
		
	}

}
