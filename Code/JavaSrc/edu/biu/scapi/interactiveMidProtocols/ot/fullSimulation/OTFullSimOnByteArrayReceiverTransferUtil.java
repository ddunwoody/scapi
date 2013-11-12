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
import edu.biu.scapi.interactiveMidProtocols.ot.OTOnByteArrayROutput;
import edu.biu.scapi.interactiveMidProtocols.ot.OTROutput;
import edu.biu.scapi.interactiveMidProtocols.ot.OTSMsg;
import edu.biu.scapi.interactiveMidProtocols.ot.OTOnByteArraySMsg;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.kdf.KeyDerivationFunction;

/**
 * This class executes the computations in the transfer function that related to the byte[] inputs.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class OTFullSimOnByteArrayReceiverTransferUtil extends OTFullSimReceiverTransferUtilAbs{

	private KeyDerivationFunction kdf; 
	
	/**
	 * Sets the given dlog, kdf and random.
	 * @param dlog
	 * @param kdf
	 * @param random
	 */
	public OTFullSimOnByteArrayReceiverTransferUtil(DlogGroup dlog, KeyDerivationFunction kdf, SecureRandom random) {
		super(dlog, random);
		this.kdf = kdf;
	}
	
	/**
	 * Run the following lines from the protocol:
	 * "IF  NOT 
	 *		1. w0, w1 in the DlogGroup, AND
	 *		2. c0, c1 are binary strings of the same length
	 *		REPORT ERROR
	 *	OUTPUT  xSigma = cSigma XOR KDF(|cSigma|,(uSigma)^r)"
	 * @param sigma input of the protocol
	 * @param r random value sampled in the protocol
	 * @param message received from the sender
	 * @return OTROutput contains xSigma
	 * @throws CheatAttemptException 
	 */
	protected OTROutput checkMessgeAndComputeX(byte sigma, BigInteger r, OTSMsg message) throws CheatAttemptException {
		//If message is not instance of OTSOnByteArrayPrivacyMessage, throw Exception.
		if(!(message instanceof OTOnByteArraySMsg)){
			throw new IllegalArgumentException("message should be instance of OTSOnByteArrayPrivacyOnlyMessage");
		}
		OTOnByteArraySMsg msg = (OTOnByteArraySMsg)message;
		
		//Reconstruct the group elements from the given message.
		GroupElement u0 = dlog.reconstructElement(true, msg.getW0());
		GroupElement u1 = dlog.reconstructElement(true, msg.getW1());
		
		//Get the byte arrays from the given message.
		byte[] c0 = msg.getC0();
		byte[] c1 = msg.getC1();
		
		//Compute the validity checks of the given message.		
		checkReceivedTuple(u0, u1, c0, c1);
		
		GroupElement kdfInput = null;
		byte[] cSigma = null;
		
		//If sigma = 0, compute u0^r and set cSigma to c0.
		if (sigma == 0){
			kdfInput = dlog.exponentiate(u0, r);
			cSigma = c0;
		} 
		
		//If sigma = 1, compute u1^r and set cSigma to c1.
		if (sigma == 1) {
			kdfInput = dlog.exponentiate(u1, r);
			cSigma = c1;
		}
		
		//Compute kdf result:
		int len = c0.length; // c0 and c1 have the same size.
		byte[] kdfBytes = dlog.mapAnyGroupElementToByteArray(kdfInput);
		byte[] xSigma = kdf.deriveKey(kdfBytes, 0, kdfBytes.length, len).getEncoded();
		
		//Xores the result from the kdf with vSigma.
		for(int i=0; i<len; i++){
			xSigma[i] = (byte) (cSigma[i] ^ xSigma[i]);
		}
		
		//Create and return the output containing xSigma
		return new OTOnByteArrayROutput(xSigma);
	}
	
	/**
	 * Run the following line from the protocol:
	 * "IF NOT 
	 *		1. u0, u1 in the DlogGroup, AND
	 *		2. c0, c1 are binary strings of the same length
	 *	   REPORT ERROR"
	 * @param c1 
	 * @param c0 
	 * @param u1 
	 * @param u0 
	 * @throws CheatAttemptException if there was a cheat attempt during the execution of the protocol.
	 */
	private void checkReceivedTuple(GroupElement u0, GroupElement u1, byte[] c0, byte[] c1) throws CheatAttemptException{
		
		if (!(dlog.isMember(u0))){
			throw new CheatAttemptException("u0 element is not a member in the current DlogGroup");
		}
		if (!(dlog.isMember(u1))){
			throw new CheatAttemptException("u1 element is not a member in the current DlogGroup");
		}
		
		if (c0.length != c1.length){
			throw new CheatAttemptException("c0 and c1 is not in the same length");
		}
	}

}
