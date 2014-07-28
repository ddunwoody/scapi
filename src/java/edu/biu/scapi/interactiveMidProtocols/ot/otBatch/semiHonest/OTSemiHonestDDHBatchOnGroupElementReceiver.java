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
package edu.biu.scapi.interactiveMidProtocols.ot.otBatch.semiHonest;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;

import edu.biu.scapi.exceptions.SecurityLevelException;
import edu.biu.scapi.interactiveMidProtocols.ot.OTSMsg;
import edu.biu.scapi.interactiveMidProtocols.ot.semiHonest.OTSemiHonestDDHOnGroupElementSenderMsg;
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.OTBatchOnGroupElementROutput;
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.OTBatchROutput;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.securityLevel.SemiHonest;

/**
 * Concrete class for batch Semi-Honest OT assuming DDH receiver ON GROUP ELEMENT.<p>
 * This class derived from OTSemiHonestDDHBatchReceiverAbs and implements the functionality 
 * related to the GroupElement inputs.<p>
 * 
 * The pseudo code of this protocol can be found in Protocol 5.1 of pseudo codes document at {@link http://crypto.biu.ac.il/scapi/SDK_Pseudocode_SCAPI_V2.0.0.pdf}.<p>
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class OTSemiHonestDDHBatchOnGroupElementReceiver extends OTSemiHonestDDHBatchReceiverAbs implements SemiHonest{
	
	/**
	 * Constructor that chooses default values of DlogGroup and SecureRandom.
	 */
	public OTSemiHonestDDHBatchOnGroupElementReceiver(){
		super();
	}
	
	/**
	 * Constructor that sets the given dlogGroup and random.
	 * @param dlog must be DDH secure.
	 * @param random
	 * @throws SecurityLevelException if the given DlogGroup is not DDH secure.
	 */
	public OTSemiHonestDDHBatchOnGroupElementReceiver(DlogGroup dlog, SecureRandom random) throws SecurityLevelException{
		
		super(dlog, random);
	}

	/**
	 * Runs the following lines from the protocol:
	 * "For every i=1,...,m, COMPUTE kISigma^(-1) = u^(-alphaI)
			For every i=1,...,m, OUTPUT  xISigma = vISigma  * (kISigma)^(-1)" 		
	 * @param sigmaArr input for the protocol
	 * @param alphaArr random values sampled by the protocol
	 * @param message received from the sender. must be OTSemiHonestDDHBatchOnGroupElementSenderMsg
	 * @return OTROutput contains xSigma
	 */
	protected OTBatchROutput computeFinalXSigma(ArrayList<Byte> sigmaArr, ArrayList<BigInteger> alphaArr, OTSMsg message) {
		//If message is not instance of OTSemiHonestDDHBatchOnGroupElementSenderMsg, throw Exception.
		if(!(message instanceof OTSemiHonestDDHBatchOnGroupElementSenderMsg)){
			throw new IllegalArgumentException("message should be instance of OTSemiHonestDDHBatchOnGroupElementSenderMsg");
		}
		
		OTSemiHonestDDHBatchOnGroupElementSenderMsg msg = (OTSemiHonestDDHBatchOnGroupElementSenderMsg)message;
		int size = sigmaArr.size();
		ArrayList<GroupElement> xSigmaArr = new ArrayList<GroupElement>();
		GroupElement u, kSigma, vSigma;
		BigInteger beta;

		for (int i=0; i<size; i++){
			
			OTSemiHonestDDHOnGroupElementSenderMsg tuple = msg.getTuples().get(i);
			//Compute (kSigma)^(-1) = u^(-alpha):
			u = dlog.reconstructElement(true, tuple.getU());	//Get u
			beta = dlog.getOrder().subtract(alphaArr.get(i));	//Get -alpha
			kSigma = dlog.exponentiate(u, beta);
			
			
			//Get v0 or v1 according to sigma.
			vSigma = null;
			if (sigmaArr.get(i) == 0){
				vSigma = dlog.reconstructElement(true, tuple.getV0());
			} else {
				vSigma = dlog.reconstructElement(true, tuple.getV1());
			}
			
			//Compue xSigma
			GroupElement xSigma = dlog.multiplyGroupElements(vSigma, kSigma);
			
			//Create and return the output containing xSigma
			xSigmaArr.add(i, xSigma);
		}
		return new OTBatchOnGroupElementROutput(xSigmaArr);
	
	}

}
