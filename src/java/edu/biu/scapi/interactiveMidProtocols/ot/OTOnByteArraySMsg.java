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
package edu.biu.scapi.interactiveMidProtocols.ot;

import edu.biu.scapi.primitives.dlog.GroupElementSendableData;

/**
 * Concrete implementation of OT Privacy sender (on byte array) message.<p>
 * In the byteArray scenario, the sender sends two GroupElement - w0 and w1 and two byte arrays - c0 and c1.
 * This class is used by most of OT implementations. <p>
 * An OT protocol that does not use this class (like OT SemiHonest) will create a separate 
 * class that matches what it needs.<p>
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class OTOnByteArraySMsg implements OTSMsg{

	private static final long serialVersionUID = 4767226698720455158L;

	private GroupElementSendableData w0;
	private GroupElementSendableData w1;
	private byte[] c0;
	private byte[] c1;
	
	/**
	 * Constructor that sets the tuples (w0,c0), (w1, c1) calculated by the protocol.
	 * @param w0 
	 * @param c0
	 * @param w1
	 * @param c1
	 */
	public OTOnByteArraySMsg(GroupElementSendableData w0, byte[] c0, 
										GroupElementSendableData w1, byte[] c1){
		this.w0 = w0;
		this.w1 = w1;
		this.c0 = c0;
		this.c1 = c1;
	}
	
	public GroupElementSendableData getW0(){
		return w0;
	}
	
	public GroupElementSendableData getW1(){
		return w1;
	}
	
	public byte[] getC0(){
		return c0;
	}
	
	public byte[] getC1(){
		return c1;
	}
}
