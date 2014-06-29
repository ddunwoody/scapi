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

import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.exceptions.SecurityLevelException;
import edu.biu.scapi.interactiveMidProtocols.ot.OTSMsg;
import edu.biu.scapi.interactiveMidProtocols.ot.semiHonest.OTSemiHonestDDHOnByteArraySenderMsg;
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.OTBatchOnByteArraySInput;
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.OTBatchSInput;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.kdf.KeyDerivationFunction;
import edu.biu.scapi.securityLevel.SemiHonest;
import edu.biu.scapi.tools.Factories.KdfFactory;

/**
 * Concrete class for batch Semi-Honest OT assuming DDH sender ON BYTE ARRAY.<p>
 * This class derived from OTSenderDDHSemiHonestAbs and implements the functionality 
 * related to the byte array inputs.<p>
 * 
 * The pseudo code of this protocol can be found in Protocol 5.1 of pseudo codes document at {@link http://crypto.biu.ac.il/scapi/SDK_Pseudocode_SCAPI_V2.0.0.pdf}.<p>
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class OTSemiHonestDDHBatchOnByteArraySender extends OTSemiHonestDDHBatchSenderAbs implements SemiHonest{
	private KeyDerivationFunction kdf; //Used in the calculation.
	
	/**
	 * Constructor that chooses default values of DlogGroup and SecureRandom.
	 */
	public OTSemiHonestDDHBatchOnByteArraySender(){
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
	public OTSemiHonestDDHBatchOnByteArraySender(DlogGroup dlog, KeyDerivationFunction kdf, SecureRandom random) throws SecurityLevelException{
		super(dlog, random);
		this.kdf = kdf;
	}

	/**
	 * Runs the following lines from the protocol:
	 * "COMPUTE:
	 *		•	v0 = x0 XOR KDF(|x0|,k0) 
	 *		•	v1 = x1 XOR KDF(|x1|,k1)"
	 * @param input MUST be an instance of OTSBatchOnByteArrayInput
	 * @param k1Array
	 * @param k0Array 
	 * @param u 
	 * @return tuple contains (u, vi0, vi1) to send to the receiver.
	 */
	protected OTSMsg computeMsg(OTBatchSInput input, GroupElement u, ArrayList<GroupElement> k0Array, ArrayList<GroupElement> k1Array) {
		//If input is not instance of OTSBatchOnByteArrayInput, throw Exception.
		if (!(input instanceof OTBatchOnByteArraySInput)){
			throw new IllegalArgumentException("input should be an instance of OTSBatchOnByteArrayInput");
		}
		
		ArrayList<byte[]> x0Arr = ((OTBatchOnByteArraySInput) input).getX0Arr();
		ArrayList<byte[]> x1Arr = ((OTBatchOnByteArraySInput) input).getX1Arr();
		int size = x0Arr.size();
		
		ArrayList<OTSemiHonestDDHOnByteArraySenderMsg> tuples = new ArrayList<OTSemiHonestDDHOnByteArraySenderMsg>();
		
		for (int i=0; i<size; i++){
			//If x0, x1 are not of the same length, throw Exception.
			int len = x0Arr.get(i).length;
			if (len != x1Arr.get(i).length){
				throw new IllegalArgumentException("x0 and x1 should be of the same length.");
			}
			
			//Calculate v0:
			//Get k0 bytes.
			byte[] k0Bytes = dlog.mapAnyGroupElementToByteArray(k0Array.get(i));
			//Calculate KDF(|x0|,k0).
			byte[] v0 = kdf.deriveKey(k0Bytes, 0, k0Bytes.length, len).getEncoded();
			
			//Xores the result from the kdf with x0.
			for(int j=0; j<len; j++){
				v0[j] = (byte) (v0[j] ^ x0Arr.get(i)[j]);
			}
			
			//Calculate v1:
			//Get k1 bytes.
			byte[] k1Bytes = dlog.mapAnyGroupElementToByteArray(k1Array.get(i));
			//Calculate KDF(|x1|,k1).
			byte[] v1 = kdf.deriveKey(k1Bytes, 0, k1Bytes.length, len).getEncoded();
			
			//Xores the result from the kdf with x1.
			for(int j=0; j<len; j++){
				v1[j] = (byte) (v1[j] ^ x1Arr.get(i)[j]);
			}
			
			tuples.add(i, new OTSemiHonestDDHOnByteArraySenderMsg(u.generateSendableData(), v0, v1));
		}
		//Return sender message.
		return new OTSemiHonestDDHBatchOnByteArraySenderMsg(tuples);
	}


}
