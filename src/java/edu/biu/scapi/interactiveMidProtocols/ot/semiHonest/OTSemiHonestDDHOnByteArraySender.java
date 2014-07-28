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

import java.security.SecureRandom;

import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.exceptions.SecurityLevelException;
import edu.biu.scapi.interactiveMidProtocols.ot.OTSInput;
import edu.biu.scapi.interactiveMidProtocols.ot.OTSMsg;
import edu.biu.scapi.interactiveMidProtocols.ot.OTOnByteArraySInput;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.kdf.KeyDerivationFunction;
import edu.biu.scapi.securityLevel.SemiHonest;
import edu.biu.scapi.tools.Factories.KdfFactory;

/**
 * Concrete class for Semi-Honest OT assuming DDH sender ON BYTE ARRAY.<p>
 * This class derived from OTSemiHonestDDHSenderAbs and implements the functionality 
 * related to the byte array inputs.<p>
 * 
 * The pseudo code of this protocol can be found in Protocol 4.1 of pseudo codes document at {@link http://crypto.biu.ac.il/scapi/SDK_Pseudocode_SCAPI_V2.0.0.pdf}.<p>
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class OTSemiHonestDDHOnByteArraySender extends OTSemiHonestDDHSenderAbs implements SemiHonest{
	private KeyDerivationFunction kdf; //Used in the calculation.
	
	/**
	 * Constructor that chooses default values of DlogGroup, kdf and SecureRandom.
	 */
	public OTSemiHonestDDHOnByteArraySender(){
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
	public OTSemiHonestDDHOnByteArraySender(DlogGroup dlog, KeyDerivationFunction kdf, SecureRandom random) throws SecurityLevelException{
		super(dlog, random);
		this.kdf = kdf;
	}

	/**
	 * Runs the following lines from the protocol:
	 * "COMPUTE:
	 *		•	v0 = x0 XOR KDF(|x0|,k0) 
	 *		•	v1 = x1 XOR KDF(|x1|,k1)"
	 * @param input MUST be an instance of OTSOnByteArrayInput
	 * @param k1 
	 * @param k0 
	 * @param u 
	 * @return tuple contains (u, v0, v1) to send to the receiver.
	 */
	protected OTSMsg computeTuple(OTSInput input, GroupElement u, GroupElement k0, GroupElement k1) {
		//If input is not instance of OTSOnByteArrayInput, throw Exception.
		if (!(input instanceof OTOnByteArraySInput)){
			throw new IllegalArgumentException("x0 and x1 should be binary strings.");
		}
		
		byte[] x0 = ((OTOnByteArraySInput) input).getX0();
		byte[] x1 = ((OTOnByteArraySInput) input).getX1();
		
		//If x0, x1 are not of the same length, throw Exception.
		if (x0.length != x1.length){
			throw new IllegalArgumentException("x0 and x1 should be of the same length.");
		}
		
		//Calculate v0:
		byte[] k0Bytes = dlog.mapAnyGroupElementToByteArray(k0);
		
		int len = x0.length;
		byte[] v0 = kdf.deriveKey(k0Bytes, 0, k0Bytes.length, len).getEncoded();
		
		//Xores the result from the kdf with x0.
		for(int i=0; i<len; i++){
			v0[i] = (byte) (v0[i] ^ x0[i]);
		}
		
		//Calculate v1:
		byte[] k1Bytes = dlog.mapAnyGroupElementToByteArray(k1);
		byte[] v1 = kdf.deriveKey(k1Bytes, 0, k1Bytes.length, len).getEncoded();
		
		//Xores the result from the kdf with x1.
		for(int i=0; i<len; i++){
			v1[i] = (byte) (v1[i] ^ x1[i]);
		}
		
		//Create and return sender message.
		return new OTSemiHonestDDHOnByteArraySenderMsg(u.generateSendableData(), v0, v1);
	}

}
