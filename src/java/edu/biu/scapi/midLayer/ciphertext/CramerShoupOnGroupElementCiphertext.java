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
 * This class is a container that encapsulates the cipher data resulting from applying the CramerShoupDDHOnGroupElement encryption.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class CramerShoupOnGroupElementCiphertext extends CramerShoupCiphertext {
	
	private GroupElement e;
	
	/**
	 * This constructor is used by the Encryption Scheme as a result of a call to function encrypt.
	 * @param u1
	 * @param u2
	 * @param e
	 * @param v
	 */
	public CramerShoupOnGroupElementCiphertext(GroupElement u1, GroupElement u2, GroupElement e, GroupElement v) {
		super(u1, u2, v);
		this.e = e;
	}
	
	public GroupElement getE() {
		return e;
	}
	public AsymmetricCiphertextSendableData generateSendableData(){
		return new CrShOnGroupElSendableData(getU1().generateSendableData(), getU2().generateSendableData(), getV().generateSendableData(), e.generateSendableData());
	}
	
	
	@Override
	public String toString() {
		String s = super.toString() + "[e=" + e + "]";
		return s;
	}

	//Nested class that holds the sendable data of the outer class
	static public class CrShOnGroupElSendableData extends CramerShoupCiphertextSendableData {

		
		private static final long serialVersionUID = 4696047521259797209L;

		private GroupElementSendableData e;
		/**
		 * @param u1
		 * @param u2
		 * @param u3
		 */
		public CrShOnGroupElSendableData(GroupElementSendableData u1,
				GroupElementSendableData u2, GroupElementSendableData u3, GroupElementSendableData e) {
			super(u1, u2, u3);
			this.e =  e;
		}
		public GroupElementSendableData getE() {
			return e;
		}

	}


}
