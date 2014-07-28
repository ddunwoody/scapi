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

import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.exceptions.SecurityLevelException;
import edu.biu.scapi.interactiveMidProtocols.ot.OTOnByteArrayROutput;
import edu.biu.scapi.interactiveMidProtocols.ot.OTROutput;
import edu.biu.scapi.interactiveMidProtocols.ot.OTSMsg;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.kdf.KeyDerivationFunction;
import edu.biu.scapi.securityLevel.SemiHonest;
import edu.biu.scapi.tools.Factories.KdfFactory;

/**
 * Concrete class for Semi-Honest OT assuming DDH receiver ON BYTE ARRAY.<p>
 * This class derived from OTSemiHonestDDHReceiverAbs and implements the functionality related to the byte array inputs.<p>
 * 
 * The pseudo code of this protocol can be found in Protocol 4.1 of pseudo codes document at {@link http://crypto.biu.ac.il/scapi/SDK_Pseudocode_SCAPI_V2.0.0.pdf}.<p>
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class OTSemiHonestDDHOnByteArrayReceiver extends OTSemiHonestDDHReceiverAbs implements SemiHonest{
	private KeyDerivationFunction kdf; //Used in the calculation.
	
	/**
	 * Constructor that chooses default values of DlogGroup and SecureRandom.
	 */
	public OTSemiHonestDDHOnByteArrayReceiver(){
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
	 */
	public OTSemiHonestDDHOnByteArrayReceiver(DlogGroup dlog, KeyDerivationFunction kdf, SecureRandom random) throws SecurityLevelException{
		
		super(dlog, random);
		this.kdf = kdf;
	}

	/**
	 * Runs the following lines from the protocol:
	 * "COMPUTE kSigma = (u)^alpha						
	 *	OUTPUT  xSigma = vSigma XOR KDF(|cSigma|,kSigma)"	
	 * @param sigma input for the protocol
	 * @param alpha random value sampled by the protocol
	 * @param message received from the sender. must be OTSOnByteArraySemiHonestMessage.
	 * @return OTROutput contains xSigma
	 */
	protected OTROutput computeFinalXSigma(byte sigma, BigInteger alpha, OTSMsg message) {
		//If message is not instance of OTSOnByteArraySemiHonestMessage, throw Exception.
		if(!(message instanceof OTSemiHonestDDHOnByteArraySenderMsg)){
			throw new IllegalArgumentException("message should be instance of OTSOnByteArraySemiHonestMessage");
		}
		
		OTSemiHonestDDHOnByteArraySenderMsg msg = (OTSemiHonestDDHOnByteArraySenderMsg)message;
		
		//Compute kSigma:
		GroupElement u = dlog.reconstructElement(true, msg.getU());
		GroupElement kSigma = dlog.exponentiate(u, alpha);
		byte[] kBytes = dlog.mapAnyGroupElementToByteArray(kSigma);
		
		//Get v0 or v1 according to sigma.
		byte[] vSigma = null;
		if (sigma == 0){
			vSigma = msg.getV0();
		} 
		if (sigma == 1) {
			vSigma = msg.getV1();
		}
		
		//Compute kdf result:
		int len = vSigma.length;
		byte[] xSigma = kdf.deriveKey(kBytes, 0, kBytes.length, len).getEncoded();
		
		//Xores the result from the kdf with vSigma.
		for(int i=0; i<len; i++){
			xSigma[i] = (byte) (vSigma[i] ^ xSigma[i]);
		}
		
		//Create and return the output containing xSigma
		return new OTOnByteArrayROutput(xSigma);
	}
	
	
}
