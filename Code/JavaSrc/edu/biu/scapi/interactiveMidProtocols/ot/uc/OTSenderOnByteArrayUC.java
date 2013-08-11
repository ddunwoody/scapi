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
package edu.biu.scapi.interactiveMidProtocols.ot.uc;

import java.security.SecureRandom;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.exceptions.SecurityLevelException;
import edu.biu.scapi.interactiveMidProtocols.ot.OTSInput;
import edu.biu.scapi.interactiveMidProtocols.ot.OTSMessage;
import edu.biu.scapi.interactiveMidProtocols.ot.OTSOnByteArrayInput;
import edu.biu.scapi.interactiveMidProtocols.ot.OTSOnByteArrayMessage;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.kdf.KeyDerivationFunction;
import edu.biu.scapi.tools.Factories.KdfFactory;

/**
 * Concrete class for OT sender based on the DDH assumption that achieves UC security in
 * the common reference string model.
 * This is implementation in BYTE ARRAY mode.
 * This class derived from OTSenderDDHUCAbs and implements the functionality 
 * related to the byte array inputs.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class OTSenderOnByteArrayUC extends OTSenderDDHUCAbs{
	
	private KeyDerivationFunction kdf; //Used in the calculation.
	
	//Protocol's inputs. ByteArrays.
	private byte[] x0;
	private byte[] x1;
	
	/**
	 * Constructor that sets the given channel, and common reference string composed of a DLOG 
	 * description (G,q,g0) and (g0,g1,h0,h1) which is a randomly chosen non-DDH tuple.
	 * @param channel
	 * @param dlog must be DDH secure.
	 * @param g0 
	 * @param g1 
	 * @param h0 
	 * @param h1 
	 * @throws SecurityLevelException if the given DlogGroup is not DDH secure.
	 */
	public OTSenderOnByteArrayUC(Channel channel, DlogGroup dlog, GroupElement g0, GroupElement g1, 
			GroupElement h0, GroupElement h1) throws SecurityLevelException{
		super(channel, dlog, g0, g1, h0, h1, new SecureRandom());
		try {
			this.kdf = KdfFactory.getInstance().getObject("HKDF(HMac(SHA-256))");
		} catch (FactoriesException e) {
			// will not occur since the given KDF name is valid.
		}
	}
	
	/**
	 * Constructor that sets the given channel, common reference string composed of a DLOG 
	 * description (G,q,g0) and (g0,g1,h0,h1) which is a randomly chosen non-DDH tuple, 
	 * kdf and random.
	 * @param channel
	 * @param dlog must be DDH secure.
	 * @param g0 
	 * @param g1 
	 * @param h0 
	 * @param h1 
	 * @param kdf
	 * @param random
	 * @throws SecurityLevelException if the given DlogGroup is not DDH secure.
	 */
	public OTSenderOnByteArrayUC(Channel channel, DlogGroup dlog, GroupElement g0, GroupElement g1, 
			GroupElement h0, GroupElement h1, KeyDerivationFunction kdf, SecureRandom random) throws SecurityLevelException{
		super(channel, dlog, g0, g1, h0, h1, random);
		this.kdf = kdf;
	}

	/**
	 * Sets the input for this OT sender.
	 * @param input MUST be OTSOnByteArrayInput with x0, x1 of the same arbitrary length.
	 */
	public void setInput(OTSInput input) {
		//If input is not instance of OTSOnByteArrayInput, throw Exception.
		if (!(input instanceof OTSOnByteArrayInput)){
			throw new IllegalArgumentException("x0 and x1 should be binary strings.");
		}
		OTSOnByteArrayInput inputStrings = (OTSOnByteArrayInput)input;
		
		//If x0, x1 are not of the same length, throw Exception.
		if (inputStrings.getX0().length != inputStrings.getX1().length){
			throw new IllegalArgumentException("x0 and x1 should be of the same length.");
		}
		
		//Set x0, x1.
		this.x0 = inputStrings.getX0();
		this.x1 = inputStrings.getX1();
	}

	/**
	 * Runs the following lines from the protocol:
	 * "COMPUTE:
	 *		•	c0 = x0 XOR KDF(|x0|,v0)
	 *		•   c1 = x1 XOR KDF(|x1|,v1)"
	 * @return tuple contains (u0,c0) and (u1,c1) to send to the receiver.
	 */
	protected OTSMessage computeTuple() {
		
		//Calculate c0:
		byte[] v0Bytes = dlog.mapAnyGroupElementToByteArray(v0);
		int len = x0.length;
		byte[] c0 = kdf.deriveKey(v0Bytes, 0, v0Bytes.length, len).getEncoded();
		
		//Xores the result from the kdf with x0.
		for(int i=0; i<len; i++){
			c0[i] = (byte) (c0[i] ^ x0[i]);
		}
		
		//Calculate v1:
		byte[] v1Bytes = dlog.mapAnyGroupElementToByteArray(v1);
		byte[] c1 = kdf.deriveKey(v1Bytes, 0, v1Bytes.length, len).getEncoded();
		
		//Xores the result from the kdf with x1.
		for(int i=0; i<len; i++){
			c1[i] = (byte) (c1[i] ^ x1[i]);
		}
		
		//Create and return sender message.
		return new OTSOnByteArrayMessage(u0.generateSendableData(), c0, u1.generateSendableData(), c1);
	}
	

}
