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

import java.security.SecureRandom;
import java.util.ArrayList;

import edu.biu.scapi.exceptions.SecurityLevelException;
import edu.biu.scapi.interactiveMidProtocols.ot.OTSMsg;
import edu.biu.scapi.interactiveMidProtocols.ot.semiHonest.OTSemiHonestDDHOnGroupElementSenderMsg;
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.OTBatchOnGroupElementSInput;
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.OTBatchSInput;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.securityLevel.SemiHonest;

/**
 * Concrete class for Batch Semi-Honest OT assuming DDH sender ON GROUP ELEMENT.<p>
 * This class derived from OTSemiHonestDDHBatchAbs and implements the functionality 
 * related to the GroupElement inputs.<p>
 * 
 * The pseudo code of this protocol can be found in Protocol 5.1 of pseudo codes document at {@link http://crypto.biu.ac.il/scapi/SDK_Pseudocode_SCAPI_V2.0.0.pdf}.<p>
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class OTSemiHonestDDHBatchOnGroupElementSender extends OTSemiHonestDDHBatchSenderAbs implements SemiHonest{
	
	/**
	 * Constructor that chooses default values of DlogGroup and SecureRandom.
	 */
	public OTSemiHonestDDHBatchOnGroupElementSender(){
		super();
	}
	
	/**
	 * Constructor that sets the given dlogGroup and random.
	 * @param dlog must be DDH secure.
	 * @param random
	 * @throws SecurityLevelException if the given DlogGroup is not DDH secure.
	 */
	public OTSemiHonestDDHBatchOnGroupElementSender(DlogGroup dlog, SecureRandom random) throws SecurityLevelException{
		super(dlog, random);
	}
	
	/**
	 * Runs the following lines from the protocol:
	 * "COMPUTE:
	 *	•   vi0 = xi0 * ki0
	 *	•	vi1 = xi1 * ki1""
	 * @param input MUST be an instance of OTSBatchOnGroupElementInput
	 * @param k1Arr 
	 * @param k0Arr 
	 * @param u 
	 * @return tuple contains (ui, vi0, vi1) to send to the receiver.
	 */
	protected OTSMsg computeMsg(OTBatchSInput input, GroupElement u, ArrayList<GroupElement> k0Arr, ArrayList<GroupElement> k1Arr) {
		//If input is not instance of OTSBatchOnGroupElementInput, throw Exception.
		if (!(input instanceof OTBatchOnGroupElementSInput)){
			throw new IllegalArgumentException("input should be an instance of OTSBatchOnGroupElementInput.");
		}
				
		//Set x0, x1.
		ArrayList<GroupElement> x0Arr = ((OTBatchOnGroupElementSInput) input).getX0Arr();
		ArrayList<GroupElement> x1Arr = ((OTBatchOnGroupElementSInput) input).getX1Arr();
		int size = x0Arr.size();
		
		ArrayList<OTSemiHonestDDHOnGroupElementSenderMsg> tuples = new ArrayList<OTSemiHonestDDHOnGroupElementSenderMsg>();
		
		for (int i=0; i<size; i++){
			//Calculate v0:
			GroupElement v0 = dlog.multiplyGroupElements(x0Arr.get(i), k0Arr.get(i));
			
			//Calculate v1:
			GroupElement v1 = dlog.multiplyGroupElements(x1Arr.get(i), k1Arr.get(i));
			
			tuples.add(i, new OTSemiHonestDDHOnGroupElementSenderMsg(u.generateSendableData(), 
								v0.generateSendableData(), v1.generateSendableData()));
		}
		
		//Create and return sender message.
		return new OTSemiHonestDDHBatchOnGroupElementSenderMsg(tuples);
	}

}
