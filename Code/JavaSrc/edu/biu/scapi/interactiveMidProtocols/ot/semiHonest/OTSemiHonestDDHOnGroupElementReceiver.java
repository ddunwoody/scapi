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
package edu.biu.scapi.interactiveMidProtocols.ot.semiHonest;

import java.math.BigInteger;
import java.security.SecureRandom;

import edu.biu.scapi.exceptions.SecurityLevelException;
import edu.biu.scapi.interactiveMidProtocols.ot.OTROnGroupElementOutput;
import edu.biu.scapi.interactiveMidProtocols.ot.OTROutput;
import edu.biu.scapi.interactiveMidProtocols.ot.OTSMessage;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.securityLevel.SemiHonest;

/**
 * Concrete class for Semi-Honest OT assuming DDH receiver ON GROUP ELEMENT.
 * This class derived from OTReceiverDDHSemiHonestAbs and implements the functionality 
 * related to the GroupElement inputs.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class OTReceiverOnGroupElementSemiHonest extends OTReceiverDDHSemiHonestAbs implements SemiHonest{
	
	/**
	 * Constructor that chooses default values of DlogGroup and SecureRandom.
	 */
	public OTReceiverOnGroupElementSemiHonest(){
		super();
	}
	
	/**
	 * Constructor that sets the given dlogGroup and random.
	 * @param dlog must be DDH secure.
	 * @param random
	 * @throws SecurityLevelException if the given DlogGroup is not DDH secure.
	 */
	public OTReceiverOnGroupElementSemiHonest(DlogGroup dlog, SecureRandom random) throws SecurityLevelException{
		
		super(dlog, random);
	}

	/**
	 * Runs the following lines from the protocol:
	 * "COMPUTE (kSigma)^(-1) = u^(-alpha)			
	 *	OUTPUT  xSigma = vSigma * (kSigma)^(-1)" 		
	 * @param sigma input for the protocol
	 * @param alpha random value sampled by the protocol
	 * @param message received from the sender. must be OTSOnGroupElementSemiHonestMessage
	 * @return OTROutput contains xSigma
	 */
	protected OTROutput computeFinalXSigma(byte sigma, BigInteger alpha, OTSMessage message) {
		//If message is not instance of OTSOnGroupElementSemiHonestMessage, throw Exception.
		if(!(message instanceof OTSOnGroupElementSemiHonestMessage)){
			throw new IllegalArgumentException("message should be instance of OTSOnGroupElementSemiHonestMessage");
		}
		
		OTSOnGroupElementSemiHonestMessage msg = (OTSOnGroupElementSemiHonestMessage)message;
		
		//Compute (kSigma)^(-1) = u^(-alpha):
		GroupElement u = dlog.reconstructElement(true, msg.getU());	//Get u
		BigInteger beta = dlog.getOrder().subtract(alpha);			//Get -alpha
		GroupElement kSigma = dlog.exponentiate(u, beta);
		
		
		//Get v0 or v1 according to sigma.
		GroupElement vSigma = null;
		if (sigma == 0){
			vSigma = dlog.reconstructElement(true, msg.getV0());
		} 
		if (sigma == 1){
			vSigma = dlog.reconstructElement(true, msg.getV1());
		}
		
		//Compue xSigma
		GroupElement xSigma = dlog.multiplyGroupElements(vSigma, kSigma);
		
		//Create and return the output containing xSigma
		return new OTROnGroupElementOutput(xSigma);
	
	}
}
