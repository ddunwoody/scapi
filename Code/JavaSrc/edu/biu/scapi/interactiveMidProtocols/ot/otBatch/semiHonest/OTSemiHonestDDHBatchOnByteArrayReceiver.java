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

import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.exceptions.SecurityLevelException;
import edu.biu.scapi.interactiveMidProtocols.ot.OTSMsg;
import edu.biu.scapi.interactiveMidProtocols.ot.semiHonest.OTSemiHonestDDHOnByteArraySenderMsg;
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.OTBatchOnByteArrayROutput;
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.OTBatchROutput;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.kdf.KeyDerivationFunction;
import edu.biu.scapi.securityLevel.SemiHonest;
import edu.biu.scapi.tools.Factories.KdfFactory;

/**
 * Concrete class for batch Semi-Honest OT assuming DDH receiver ON BYTE ARRAY. <p>
 * This class derived from OTSemiHonestDDHBatchReceiverAbs and implements the functionality 
 * related to the byte array inputs.<p>
 * 
 * The pseudo code of this protocol can be found in Protocol 5.1 of pseudo codes document at {@link http://crypto.biu.ac.il/scapi/SDK_Pseudocode_SCAPI_V2.0.0.pdf}.<p>
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class OTSemiHonestDDHBatchOnByteArrayReceiver extends OTSemiHonestDDHBatchReceiverAbs implements SemiHonest{
	private KeyDerivationFunction kdf; //Used in the calculation.
	
	/**
	 * Constructor that chooses default values of DlogGroup and SecureRandom.
	 */
	public OTSemiHonestDDHBatchOnByteArrayReceiver(){
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
	public OTSemiHonestDDHBatchOnByteArrayReceiver(DlogGroup dlog, KeyDerivationFunction kdf, SecureRandom random) throws SecurityLevelException{
		
		super(dlog, random);
		this.kdf = kdf;
	}

	/**
	 * Runs the following lines from the protocol:
	 * "For every i=1,...,m, COMPUTE kISigma = u^alphaI
		For every i=1,...,m, OUTPUT  xISigma = vISigma XOR KDF(|vISigma|,kISigma)"	
	 * @param sigmaArr input for the protocol
	 * @param alphaArr random values sampled by the protocol
	 * @param message received from the sender. must be OTSemiHonestDDHBatchOnByteArraySenderMsg.
	 * @return OTROutput contains xSigma
	 */
	protected OTBatchROutput computeFinalXSigma(ArrayList<Byte> sigmaArr, ArrayList<BigInteger> alphaArr, OTSMsg message) {
		//If message is not instance of OTSOnByteArraySemiHonestMessage, throw Exception.
		if(!(message instanceof OTSemiHonestDDHBatchOnByteArraySenderMsg)){
			throw new IllegalArgumentException("message should be instance of OTSemiHonestDDHBatchOnByteArraySenderMsg");
		}
		
		OTSemiHonestDDHBatchOnByteArraySenderMsg msg = (OTSemiHonestDDHBatchOnByteArraySenderMsg)message;
		int size = sigmaArr.size();
		ArrayList<byte[]> xSigmaArr = new ArrayList<byte[]> ();
		GroupElement u, kSigma;
		byte[] vSigma, xSigma;

		for (int i=0; i<size; i++){
			
			OTSemiHonestDDHOnByteArraySenderMsg tuple = msg.getTuples().get(i);
			//Compute kSigma:
			u = dlog.reconstructElement(true, tuple.getU());
			kSigma = dlog.exponentiate(u, alphaArr.get(i));
			byte[] kBytes = dlog.mapAnyGroupElementToByteArray(kSigma);
			
			//Get v0 or v1 according to sigma.
			if (sigmaArr.get(i) == 0){
				vSigma = tuple.getV0();
			} else {
				vSigma = tuple.getV1();
			}
			
			//Compute kdf result:
			int len = vSigma.length;
			xSigma = kdf.deriveKey(kBytes, 0, kBytes.length, len).getEncoded();
			
			//Xores the result from the kdf with vSigma.
			for(int j=0; j<len; j++){
				xSigma[j] = (byte) (vSigma[j] ^ xSigma[j]);
			}
			xSigmaArr.add(i, xSigma);
		}
		//Create and return the output containing xSigma
		return new OTBatchOnByteArrayROutput(xSigmaArr);
	}
}
