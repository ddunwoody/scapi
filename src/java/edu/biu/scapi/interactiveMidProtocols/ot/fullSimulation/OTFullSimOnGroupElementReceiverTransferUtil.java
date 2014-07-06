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
package edu.biu.scapi.interactiveMidProtocols.ot.fullSimulation;

import java.math.BigInteger;
import java.security.SecureRandom;

import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.interactiveMidProtocols.ot.OTOnGroupElementROutput;
import edu.biu.scapi.interactiveMidProtocols.ot.OTROutput;
import edu.biu.scapi.interactiveMidProtocols.ot.OTSMsg;
import edu.biu.scapi.interactiveMidProtocols.ot.OTOnGroupElementSMsg;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;

/**
 * This class executes the computations in the transfer function that related to the GroupElement inputs.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class OTFullSimOnGroupElementReceiverTransferUtil extends OTFullSimReceiverTransferUtilAbs{

	/**
	 * Sets the given dlog and random.
	 * @param dlog
	 * @param random
	 */
	public OTFullSimOnGroupElementReceiverTransferUtil(DlogGroup dlog, SecureRandom random) {
		super(dlog, random);
		
	}

	/**
	 * Run the following lines from the protocol:
	 * "COMPUTE xSigma = cSigma * (uSigma)^(-r)"
	 * @param sigma input of the protocol
	 * @param r random value sampled in the protocol
	 * @param message received from the sender
	 * @return OTROutput contains xSigma
	 * @throws CheatAttemptException 
	 */
	protected OTROutput checkMessgeAndComputeX(byte sigma, BigInteger r, OTSMsg message) throws CheatAttemptException {
		//If message is not instance of OTSOnGroupElementMessage, throw Exception.
		if(!(message instanceof OTOnGroupElementSMsg)){
			throw new IllegalArgumentException("message should be instance of OTSOnGroupElementMessage");
		}
		
		OTOnGroupElementSMsg msg = (OTOnGroupElementSMsg)message;
		
		//Reconstruct the group elements from the given message.
		GroupElement u0 = dlog.reconstructElement(true, msg.getW0());
		GroupElement u1 = dlog.reconstructElement(true, msg.getW1());
		GroupElement c0 = dlog.reconstructElement(true, msg.getC0());
		GroupElement c1 = dlog.reconstructElement(true, msg.getC1());
				
		//Compute the validity checks of the given message.		
		checkReceivedTuple(u0, u1, c0, c1);
				
		GroupElement xSigma = null;
		GroupElement cSigma = null;
		BigInteger minusR = dlog.getOrder().subtract(r);
		
		//If sigma = 0, compute (uSigma)^(-r) and set cSigma to c0.
		if (sigma == 0){
			xSigma = dlog.exponentiate(u0, minusR);
			cSigma = c0;
		} 
		
		//If sigma = 1, compute w1^beta and set cSigma to c1.
		if (sigma == 1) {
			xSigma = dlog.exponentiate(u1, minusR);
			cSigma = c1;
		}
		
		xSigma = dlog.multiplyGroupElements(cSigma, xSigma);
		
		//Create and return the output containing xSigma
		return new OTOnGroupElementROutput(xSigma);
	}
	
	/**
	 * Run the following line from the protocol:
	 * "IF  NOT 
	 *		1. u0, u1, c0, c1 in the DlogGroup
	 *	REPORT ERROR"
	 * @param c1 
	 * @param c0 
	 * @param u1 
	 * @param u0 
	 * @throws CheatAttemptException if there was a cheat attempt during the execution of the protocol.
	 */
	private void checkReceivedTuple(GroupElement u0, GroupElement u1, GroupElement c0, GroupElement c1) throws CheatAttemptException{
		
		if (!(dlog.isMember(u0))){
			throw new CheatAttemptException("u0 element is not a member in the current DlogGroup");
		}
		if (!(dlog.isMember(u1))){
			throw new CheatAttemptException("u1 element is not a member in the current DlogGroup");
		}
		if (!(dlog.isMember(c0))){
			throw new CheatAttemptException("c0 element is not a member in the current DlogGroup");
		}
		if (!(dlog.isMember(c1))){
			throw new CheatAttemptException("c1 element is not a member in the current DlogGroup");
		}
		
	}
}
