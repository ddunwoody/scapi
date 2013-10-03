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
package edu.biu.scapi.interactiveMidProtocols.ot.uc;

import java.security.SecureRandom;

import edu.biu.scapi.exceptions.SecurityLevelException;
import edu.biu.scapi.interactiveMidProtocols.ot.OTSInput;
import edu.biu.scapi.interactiveMidProtocols.ot.OTSMessage;
import edu.biu.scapi.interactiveMidProtocols.ot.OTSOnGroupElementInput;
import edu.biu.scapi.interactiveMidProtocols.ot.OTSOnGroupElementMessage;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.securityLevel.Malicious;

/**
 * Concrete class for OT sender based on the DDH assumption that achieves UC security in
 * the common reference string model.
 * This is implementation in GroupElement mode.
 * 
 * This class derived from OTSenderDDHUCAbs and implements the functionality 
 * related to the byte array inputs.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class OTSenderOnGroupElementUC extends OTSenderDDHUCAbs implements Malicious{
	
	/**
	 * Constructor that sets the given common reference string composed of a DLOG 
	 * description (G,q,g0) and (g0,g1,h0,h1) which is a randomly chosen non-DDH tuple, 
	 * kdf and random.
	 * @param dlog must be DDH secure.
	 * @param g0 
	 * @param g1 
	 * @param h0 
	 * @param h1 
	 * @param kdf
	 * @param random
	 * @throws SecurityLevelException if the given DlogGroup is not DDH secure.
	 */
	public OTSenderOnGroupElementUC(DlogGroup dlog, GroupElement g0, 
			GroupElement g1, GroupElement h0, GroupElement h1, SecureRandom random) throws SecurityLevelException{
		super(dlog, g0, g1, h0, h1, random);
	}
	
	/**
	 * Runs the following lines from the protocol:
	 * "COMPUTE:
	 *		•	c0 = x0 * v0<p>
	 *		•	c1 = x1 * v1"
	 * @param input MUST be OTSOnGroupElementInput.
	 * @param v1 
	 * @param v0 
	 * @param u1 
	 * @param u0 
	 * @return tuple contains (u0,c0) and (u1,c1) to send to the receiver.
	 */
	protected OTSMessage computeTuple(OTSInput input, GroupElement u0, GroupElement u1, GroupElement v0, GroupElement v1) {
		//If input is not instance of OTSOnGroupElementInput, throw Exception.
		if (!(input instanceof OTSOnGroupElementInput)){
			throw new IllegalArgumentException("x0 and x1 should be DlogGroup elements.");
		}
		OTSOnGroupElementInput inputElements = (OTSOnGroupElementInput)input;
		
		//Set x0, x1.
		GroupElement x0 = inputElements.getX0();
		GroupElement x1 = inputElements.getX1();
		
		//Calculate c0:
		GroupElement c0 = dlog.multiplyGroupElements(x0, v0);
		
		//Calculate c1:
		GroupElement c1 = dlog.multiplyGroupElements(x1, v1);
		
		//Create and return sender message.
		return new OTSOnGroupElementMessage(u0.generateSendableData(), c0.generateSendableData(), 
				u1.generateSendableData(), c1.generateSendableData());
	}

}
