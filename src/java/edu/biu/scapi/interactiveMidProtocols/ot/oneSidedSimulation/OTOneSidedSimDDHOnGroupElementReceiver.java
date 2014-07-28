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
package edu.biu.scapi.interactiveMidProtocols.ot.oneSidedSimulation;

import java.math.BigInteger;
import java.security.SecureRandom;

import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.exceptions.InvalidDlogGroupException;
import edu.biu.scapi.exceptions.SecurityLevelException;
import edu.biu.scapi.interactiveMidProtocols.ot.OTOnGroupElementROutput;
import edu.biu.scapi.interactiveMidProtocols.ot.OTROutput;
import edu.biu.scapi.interactiveMidProtocols.ot.OTSMsg;
import edu.biu.scapi.interactiveMidProtocols.ot.OTOnGroupElementSMsg;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.securityLevel.OneSidedSimulation;

/**
 * Concrete implementation of the receiver side in oblivious transfer based on the DDH assumption that achieves 
 * privacy for the case that the sender is corrupted and simulation in the case that the receiver 
 * is corrupted.<p>
 * 
 * This class derived from OTOneSidedSimDDHReceiverAbs and implements the functionality 
 * related to the GroupElement inputs.<p>
 * 
 * For more information see Protocol 7.3 page 185 of <i>Efficient Secure Two-Party Protocols</i> by Hazay-Lindell. <P>
 * The pseudo code of this protocol can be found in Protocol 4.3 of pseudo codes document at {@link http://crypto.biu.ac.il/scapi/SDK_Pseudocode_SCAPI_V2.0.0.pdf}.<p>
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class OTOneSidedSimDDHOnGroupElementReceiver extends OTOneSidedSimDDHReceiverAbs implements OneSidedSimulation{

	/**
	 * Constructor that chooses default values of DlogGroup and SecureRandom.
	 */
	public OTOneSidedSimDDHOnGroupElementReceiver(){
		super();
	}
	
	/**
	 * Constructor that sets the given dlogGroup and random.
	 * @param dlog must be DDH secure.
	 * @param random
	 * @throws SecurityLevelException if the given DlogGroup is not DDH secure.
	 * @throws InvalidDlogGroupException if the given dlog is invalid.
	 */
	public OTOneSidedSimDDHOnGroupElementReceiver(DlogGroup dlog, SecureRandom random) throws SecurityLevelException, InvalidDlogGroupException{
		
		super(dlog, random);
	}

	/**
	 * Run the following line from the protocol:
	 * "IF  NOT 
	 *		1. w0, w1, c0, c1 in the DlogGroup
	 *	REPORT ERROR"
	 * @param c1 
	 * @param c0 
	 * @param w1 
	 * @param w0 
	 * @throws CheatAttemptException if there was a cheat attempt during the execution of the protocol.
	 */
	private void checkReceivedTuple(GroupElement w0, GroupElement w1, GroupElement c0, GroupElement c1) throws CheatAttemptException{
		
		if (!(dlog.isMember(w0))){
			throw new CheatAttemptException("w0 element is not a member in the current DlogGroup");
		}
		if (!(dlog.isMember(w1))){
			throw new CheatAttemptException("w1 element is not a member in the current DlogGroup");
		}
		if (!(dlog.isMember(c0))){
			throw new CheatAttemptException("c0 element is not a member in the current DlogGroup");
		}
		if (!(dlog.isMember(c1))){
			throw new CheatAttemptException("c1 element is not a member in the current DlogGroup");
		}	
	}

	/**
	 * Run the following lines from the protocol:
	 * "IF  NOT 
	 *		1. w0, w1, c0, c1 in the DlogGroup
	 *	REPORT ERROR
	 *  COMPUTE (kSigma)^(-1) = (wSigma)^(-beta)
	 *	OUTPUT  xSigma = cSigma * (kSigma)^(-1)"
	 * @param sigma input of the protocol
	 * @param beta random value sampled in the protocol
	 * @param message received from the sender
	 * @return OTROutput contains xSigma
	 * @throws CheatAttemptException 
	 */
	protected OTROutput checkMessgeAndComputeX(byte sigma, BigInteger beta, OTSMsg message) throws CheatAttemptException {
		//If message is not instance of OTSOnGroupElementPrivacyMessage, throw Exception.
		if(!(message instanceof OTOnGroupElementSMsg)){
			throw new IllegalArgumentException("message should be instance of OTSOnGroupElementPrivacyOnlyMessage");
		}
		
		OTOnGroupElementSMsg msg = (OTOnGroupElementSMsg)message;
		
		//Reconstruct the group elements from the given message.
		GroupElement w0 = dlog.reconstructElement(true, msg.getW0());
		GroupElement w1 = dlog.reconstructElement(true, msg.getW1());
		GroupElement c0 = dlog.reconstructElement(true, msg.getC0());
		GroupElement c1 = dlog.reconstructElement(true, msg.getC1());
				
		//Compute the validity checks of the given message.
		checkReceivedTuple(w0, w1, c0, c1);
				
		GroupElement kSigma = null;
		GroupElement cSigma = null;
		BigInteger minusBeta = dlog.getOrder().subtract(beta);
		
		//If sigma = 0, compute w0^beta and set cSigma to c0.
		if (sigma == 0){
			kSigma = dlog.exponentiate(w0, minusBeta);
			cSigma = c0;
		} 
		
		//If sigma = 0, compute w1^beta and set cSigma to c1.
		if (sigma == 1) {
			kSigma = dlog.exponentiate(w1, minusBeta);
			cSigma = c1;
		}
		
		GroupElement xSigma = dlog.multiplyGroupElements(cSigma, kSigma);
		
		//Create and return the output containing xSigma
		return new OTOnGroupElementROutput(xSigma);
	}

}
