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


package edu.biu.scapi.midLayer.plaintext;

import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.dlog.GroupElementSendableData;

/**
 * This class holds the plaintext as a GroupElement.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class GroupElementPlaintext implements Plaintext {

	private GroupElement element;
	
	public GroupElementPlaintext(GroupElement el){
		element = el;
	}
	
	public GroupElement getElement(){
		return element;
	}
	
	@Override
	public boolean equals(Object plaintext){
		if (!(plaintext instanceof GroupElementPlaintext)){
			return false;
		}
		GroupElement el = ((GroupElementPlaintext) plaintext).getElement();
		
		if (!element.equals(el)){
			return false;
		} 
		
		return true;
	}
	
	

	@Override
	public String toString() {
		return "GroupElementPlaintext [element=" + element + "]";
	}

	/**
	 * @see edu.biu.scapi.midLayer.plaintext.Plaintext#generateSendableData()
	 */
	@Override
	public PlaintextSendableData generateSendableData() {
		return new GroupElementPlaintextSendableData(element.generateSendableData());
	}
	
	//Nested class that holds the sendable data of the outer class
	static public class GroupElementPlaintextSendableData implements PlaintextSendableData {

		private static final long serialVersionUID = -5267306672307327063L;

		GroupElementSendableData groupElementData;

		public GroupElementPlaintextSendableData(
				GroupElementSendableData groupElementData) {
			super();
			this.groupElementData = groupElementData;
		}

		public GroupElementSendableData getGroupElement() {
			return groupElementData;
		}

		@Override
		public String toString() {
			return "GroupElementPlaintextSendableData [groupElementData="
					+ groupElementData + "]";
		}
		
		
	}
}
