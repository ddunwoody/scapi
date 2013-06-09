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

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.interactiveMidProtocols.ot.OTSInput;
import edu.biu.scapi.interactiveMidProtocols.ot.OTSMessage;
import edu.biu.scapi.interactiveMidProtocols.ot.OTSOnByteArrayInput;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.kdf.KeyDerivationFunction;
import edu.biu.scapi.securityLevel.SemiHonest;

/**
 * Concrete class for Semi-Honest OT assuming DDH sender ON BYTE ARRAY.
 * This class derived from OTSenderDDHSemiHonestAbs and implements the functionality 
 * related to the byte array inputs.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class OTSenderOnByteArraySemiHonest extends OTSenderDDHSemiHonestAbs implements SemiHonest{
	private KeyDerivationFunction kdf; //Used in the calculation.
	
	//Protocol's inputs. ByteArrays.
	private byte[] x0;
	private byte[] x1;
	
	/**
	 * Constructor that gets the channel and chooses default values of DlogGroup and SecureRandom.
	 */
	public OTSenderOnByteArraySemiHonest(Channel channel){
		super(channel);
	}
	
	/**
	 * Constructor that sets the given channel, dlogGroup, kdf and random.
	 * @param channel
	 * @param dlog must be DDH secure.
	 * @param kdf
	 * @param random
	 */
	public OTSenderOnByteArraySemiHonest(Channel channel, DlogGroup dlog, KeyDerivationFunction kdf, SecureRandom random){
		super(channel, dlog, random);
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
		if (inputStrings.getX0().length != inputStrings.getX0().length){
			throw new IllegalArgumentException("x0 and x1 should be of the same length.");
		}
		
		//Set x0, x1.
		this.x0 = inputStrings.getX0();
		this.x1 = inputStrings.getX1();
	}

	/**
	 * Runs the following lines from the protocol:
	 * "COMPUTE:
	 *		•	v0 = x0 XOR KDF(|x0|,k0) 
	 *		•	v1 = x1 XOR KDF(|x1|,k1)"
	 * @return tuple contains (u, v0, v1) to send to the receiver.
	 */
	protected OTSMessage computeTuple() {
		
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
		return new OTSOnByteArraySemiHonestMessage(u.generateSendableData(), v0, v1);
	}

}
