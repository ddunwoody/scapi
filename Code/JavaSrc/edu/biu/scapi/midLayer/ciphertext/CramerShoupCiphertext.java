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

import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.dlog.GroupElementSendableData;

public abstract class CramerShoupCiphertext implements AsymmetricCiphertext{

	private GroupElement u1;
	private GroupElement u2;
	private GroupElement v;
	
	public CramerShoupCiphertext(GroupElement u1, GroupElement u2, GroupElement v) {
		this.u1 = u1;
		this.u2 = u2;
		this.v = v;
	}

	public GroupElement getU1() {
		return u1;
	}

	public GroupElement getU2() {
		return u2;
	}

	public GroupElement getV() {
		return v;
	}
	
	
	
	@Override
	public String toString() {
		return "CramerShoupCiphertext [u1=" + u1 + ", u2=" + u2 + ", v=" + v
				+ "]";
	}


	//Nested class that holds the sendable data of the outer class
	static public abstract class CramerShoupCiphertextSendableData implements AsymmetricCiphertextSendableData {

		private static final long serialVersionUID = -6925856352814870257L;
		
		GroupElementSendableData u1;
		GroupElementSendableData u2;
		GroupElementSendableData v;
		
		public CramerShoupCiphertextSendableData(GroupElementSendableData u1, GroupElementSendableData u2, GroupElementSendableData v) {
			super();
			this.u1 = u1;
			this.u2 = u2;
			this.v = v;
		}

	
		public GroupElementSendableData getU1() {
			return u1;
		}

		public GroupElementSendableData getU2() {
			return u2;
		}

		public GroupElementSendableData getV() {
			return v;
		}
		
		
	}

}
