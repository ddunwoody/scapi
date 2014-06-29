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
package edu.biu.scapi.interactiveMidProtocols.ot.privacyOnly;

import java.math.BigInteger;
import java.security.SecureRandom;

import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.exceptions.InvalidDlogGroupException;
import edu.biu.scapi.exceptions.SecurityLevelException;
import edu.biu.scapi.interactiveMidProtocols.ot.OTOnByteArrayROutput;
import edu.biu.scapi.interactiveMidProtocols.ot.OTROutput;
import edu.biu.scapi.interactiveMidProtocols.ot.OTSMsg;
import edu.biu.scapi.interactiveMidProtocols.ot.OTOnByteArraySMsg;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.kdf.KeyDerivationFunction;
import edu.biu.scapi.securityLevel.PrivacyOnly;
import edu.biu.scapi.tools.Factories.KdfFactory;

/**
 * Concrete class for OT Privacy assuming DDH receiver ON BYTE ARRAY.<p>
 * This class derived from OTPrivacyOnlyDDHReceiverAbs and implements the functionality 
 * related to the byte array inputs. <p>
 * 
 * For more information see Protocol 7.2.1 page 179 of <i>Efficient Secure Two-Party Protocols</i> by Hazay-Lindell.<p>
 * The pseudo code of this protocol can be found in Protocol 4.2 of pseudo codes document at {@link http://crypto.biu.ac.il/scapi/SDK_Pseudocode_SCAPI_V2.0.0.pdf}.<p>
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class OTPrivacyOnlyDDHOnByteArrayReceiver extends OTPrivacyOnlyDDHReceiverAbs implements PrivacyOnly{
	
	private KeyDerivationFunction kdf; //Used in the calculation.
	
	/**
	 * Constructor that chooses default values of DlogGroup and SecureRandom.
	 */
	public OTPrivacyOnlyDDHOnByteArrayReceiver(){
		super();
		try {
			this.kdf = KdfFactory.getInstance().getObject("HKDF(HMac(SHA-256))");
		} catch (FactoriesException e) {
			// will not occur since the given KDF name is valid.
		}
	}
	
	/**
	 * Constructor that sets the given dlogGroup, kdf and random.
	 * @param dlog must be DDH secure.
	 * @param kdf
	 * @param random
	 * @throws SecurityLevelException if the given DlogGroup is not DDH secure.
	 * @throws InvalidDlogGroupException if the given dlog is invalid.
	 */
	public OTPrivacyOnlyDDHOnByteArrayReceiver(DlogGroup dlog, KeyDerivationFunction kdf, SecureRandom random) throws SecurityLevelException, InvalidDlogGroupException{
		
		super(dlog, random);
		this.kdf = kdf;
	}
	
	/**
	 * Run the following line from the protocol:
	 * "IF NOT 
	 *		1. w0, w1 in the DlogGroup, AND
	 *		2. c0, c1 are binary strings of the same length
	 *	   REPORT ERROR"
	 * @param c1 
	 * @param c0 
	 * @param w1 
	 * @param w0 
	 * @throws CheatAttemptException if there was a cheat attempt during the execution of the protocol.
	 */
	private void checkReceivedTuple(GroupElement w0, GroupElement w1, byte[] c0, byte[] c1) throws CheatAttemptException{
		
		if (!(dlog.isMember(w0))){
			throw new CheatAttemptException("w0 element is not a member in the current DlogGroup");
		}
		if (!(dlog.isMember(w1))){
			throw new CheatAttemptException("w1 element is not a member in the current DlogGroup");
		}
		
		if (c0.length != c1.length){
			throw new CheatAttemptException("c0 and c1 is not in the same length");
		}
	}

	/**
	 * Run the following lines from the protocol:
	 * "IF  NOT 
	 *			1. w0, w1 in the DlogGroup, AND
	 *			2. c0, c1 are binary strings of the same length
	 *		   REPORT ERROR
	 *  COMPUTE kSigma = (wSigma)^beta
	 *	OUTPUT  xSigma = cSigma XOR KDF(|cSigma|,kSigma)"
	 * @param sigma input of the protocol
	 * @param beta random value sampled in the protocol
	 * @param message received from the sender
	 * @return OTROutput contains xSigma
	 * @throws CheatAttemptException 
	 */
	protected OTROutput checkMessgeAndComputeX(byte sigma, BigInteger beta, OTSMsg message) throws CheatAttemptException {
		//If message is not instance of OTSOnByteArrayMessage, throw Exception.
		if(!(message instanceof OTOnByteArraySMsg)){
			throw new IllegalArgumentException("message should be instance of OTSOnByteArrayMessage");
		}
		
		OTOnByteArraySMsg msg = (OTOnByteArraySMsg)message;
		
		//Reconstruct the group elements from the given message.
		GroupElement w0 = dlog.reconstructElement(true, msg.getW0());
		GroupElement w1 = dlog.reconstructElement(true, msg.getW1());
		
		//Get the byte arrays from the given message.
		byte[] c0 = msg.getC0();
		byte[] c1 = msg.getC1();
		
		//Compute the validity checks of the given message.
		checkReceivedTuple(w0, w1, c0, c1);
		
		GroupElement kSigma = null;
		byte[] cSigma = null;
		
		//If sigma = 0, compute w0^beta and set cSigma to c0.
		if (sigma == 0){
			kSigma = dlog.exponentiate(w0, beta);
			cSigma = c0;
		} 
		
		//If sigma = 0, compute w1^beta and set cSigma to c1.
		if (sigma == 1) {
			kSigma = dlog.exponentiate(w1, beta);
			cSigma = c1;
		}
		
		//Compute kdf result:
		int len = c0.length; // c0 and c1 have the same size.
		byte[] kBytes = dlog.mapAnyGroupElementToByteArray(kSigma);
		byte[] xSigma = kdf.deriveKey(kBytes, 0, kBytes.length, len).getEncoded();
		
		//Xores the result from the kdf with vSigma.
		for(int i=0; i<len; i++){
			xSigma[i] = (byte) (cSigma[i] ^ xSigma[i]);
		}
		
		//Create and return the output containing xSigma
		return new OTOnByteArrayROutput(xSigma);
	}

}
