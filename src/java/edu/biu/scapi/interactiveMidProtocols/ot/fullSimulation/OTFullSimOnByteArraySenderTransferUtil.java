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

import java.security.SecureRandom;

import edu.biu.scapi.interactiveMidProtocols.ot.OTSInput;
import edu.biu.scapi.interactiveMidProtocols.ot.OTSMsg;
import edu.biu.scapi.interactiveMidProtocols.ot.OTOnByteArraySInput;
import edu.biu.scapi.interactiveMidProtocols.ot.OTOnByteArraySMsg;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.kdf.KeyDerivationFunction;

/**
 * This class executes the computations in the transfer function that related to the byte[] inputs.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class OTFullSimOnByteArraySenderTransferUtil extends OTFullSimSenderTransferUtilAbs{

	private KeyDerivationFunction kdf; 
	
	/**
	 * Sets the given dlog, kdf and random.
	 * @param dlog
	 * @param kdf
	 * @param random
	 */
	public OTFullSimOnByteArraySenderTransferUtil(DlogGroup dlog, KeyDerivationFunction kdf, SecureRandom random) {
		super(dlog, random);
		this.kdf = kdf;
		
	}

	/**
	 * Runs the following lines from the protocol:
	 * "COMPUTE:
	 *		COMPUTE c0 = x0 XOR KDF(|x0|,v0)
	 *		COMPUTE c1 = x1 XOR KDF(|x1|,v1)"
	 * @param input must be a OTSOnByteArrayInput.
	 * @param u0
	 * @param u1
	 * @param v0
	 * @param v1
	 * @return tuple contains (u0, c0, u1, c1) to send to the receiver.
	 */
	protected OTSMsg computeTuple(OTSInput input, GroupElement u0, GroupElement u1, GroupElement v0, GroupElement v1) {
		//If input is not instance of OTSOnByteArrayInput, throw Exception.
		if (!(input instanceof OTOnByteArraySInput)){
			throw new IllegalArgumentException("x0 and x1 should be binary strings.");
		}
		OTOnByteArraySInput inputStrings = (OTOnByteArraySInput)input;
		
		//If x0, x1 are not of the same length, throw Exception.
		if (inputStrings.getX0().length != inputStrings.getX1().length){
			throw new IllegalArgumentException("x0 and x1 should be of the same length.");
		}
		
		//Get x0, x1.
		byte[] x0 = inputStrings.getX0();
		byte[] x1 = inputStrings.getX1();
				
		//Calculate c0:
		byte[] v0Bytes = dlog.mapAnyGroupElementToByteArray(v0);
		int len = x0.length;
		byte[] c0 = kdf.deriveKey(v0Bytes, 0, v0Bytes.length, len).getEncoded();
		
		//Xores the result from the kdf with x0.
		for(int i=0; i<len; i++){
			c0[i] = (byte) (c0[i] ^ x0[i]);
		}
		
		//Calculate c1:
		byte[] v1Bytes = dlog.mapAnyGroupElementToByteArray(v1);
		byte[] c1 = kdf.deriveKey(v1Bytes, 0, v1Bytes.length, len).getEncoded();
		
		//Xores the result from the kdf with x1.
		for(int i=0; i<len; i++){
			c1[i] = (byte) (c1[i] ^ x1[i]);
		}
		
		//Create and return sender message.
		return new OTOnByteArraySMsg(u0.generateSendableData(), c0, u1.generateSendableData(), c1);
	}

}
