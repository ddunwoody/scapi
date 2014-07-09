/**
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
Copyright (c) 2012 - SCAPI (http://crypto.biu.ac.il/scapi)
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

package edu.biu.scapi.interactiveMidProtocols.commitmentScheme.pedersenHash;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.InvalidDlogGroupException;
import edu.biu.scapi.exceptions.SecurityLevelException;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtByteArrayCommitValue;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCCommitmentMsg;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCDecommitmentMessage;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtReceiver;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCommitValue;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtOnByteArray;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.pedersen.CmtPedersenDecommitmentMessage;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.pedersen.CmtPedersenReceiverCore;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.hash.CryptographicHash;
import edu.biu.scapi.primitives.hash.openSSL.OpenSSLSHA224;
import edu.biu.scapi.securityLevel.PerfectlyHidingCmt;

/**
 * Concrete implementation of receiver that executes the Pedersen hash commitment 
 * scheme in the receiver's point of view.<p>
 * 
 * This is a perfectly-hiding commitment that can be used to commit to a value of any length. <p>
 * 
 * For more information see Protocol 6.5.3, page 164 of <i>Efficient Secure Two-Party Protocols</i> by Hazay-Lindell.<p>
 * The pseudo code of this protocol can be found in Protocol 3.2 of pseudo codes document at {@link http://crypto.biu.ac.il/scapi/SDK_Pseudocode_SCAPI_V2.0.0.pdf}.<p>
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class CmtPedersenHashReceiver extends CmtPedersenReceiverCore implements CmtReceiver, PerfectlyHidingCmt, CmtOnByteArray{
	
	/*
	 * runs the following protocol:
	 * "Run COMMIT_PEDERSEN to commit to value H(x). 
	 * For decommitment, send x and the receiver verifies that the commitment was to H(x). "
	 */
	
	private CryptographicHash hash;
	
	/**
	 * This constructor uses a default Dlog Group and default Cryptographic Hash. They keep the condition that 
	 * the size in bytes of the resulting hash is less than the size in bytes of the order of the DlogGroup.
	 * An established channel has to be provided by the user of the class.
	 * @param channel
	 * @throws IOException if there was a problem in the communication.
	 */
	public CmtPedersenHashReceiver(Channel channel) throws IOException {
		super(channel);
		hash = new OpenSSLSHA224(); 		//This default hash suits the default DlogGroup of the underlying Committer.
	}
	
	/**
	 * This constructor receives as arguments an instance of a Dlog Group and an instance 
	 * of a Cryptographic Hash such that they keep the condition that the size in bytes 
	 * of the resulting hash is less than the size in bytes of the order of the DlogGroup.
	 * Otherwise, it throws IllegalArgumentException.
	 * An established channel has to be provided by the user of the class.
 	 * @param channel an established channel obtained via the Communication Layer 
	 * @param dlog 
	 * @param hash
	 * @param random
	 * @throws IllegalArgumentException if the size in bytes of the resulting hash is bigger than the size in bytes of the order of the DlogGroup
	 * @throws SecurityLevelException if the Dlog Group is not DDH
	 * @throws InvalidDlogGroupException if the parameters of the group do not conform the type the group is supposed to be
	 * @throws IOException if there was a problem during the communication
	 */
	public CmtPedersenHashReceiver(Channel channel, DlogGroup dlog, CryptographicHash hash, SecureRandom random) throws IllegalArgumentException,  IOException, SecurityLevelException, InvalidDlogGroupException{
		super(channel, dlog, random);
		if (hash.getHashedMsgSize()> (dlog.getOrder().bitLength()/8)){
			throw new IllegalArgumentException("The size in bytes of the resulting hash is bigger than the size in bytes of the order of the DlogGroup.");
		}
		this.hash = hash;
	}

	/**
	 * Verifies that the commitment was to H(x).
	 */
	@Override
	public CmtCommitValue verifyDecommitment(CmtCCommitmentMsg commitmentMsg, CmtCDecommitmentMessage decommitmentMsg) {
		//Hash the input x with the hash function
		byte[] x  = ((CmtPedersenDecommitmentMessage)decommitmentMsg).getX().toByteArray();
		//calculate H(x) = Hash(x)
		byte[] hashValArray = new byte[hash.getHashedMsgSize()];
		hash.update(x, 0, x.length);
		hash.hashFinal(hashValArray, 0);
		
		CmtCommitValue val = super.verifyDecommitment(commitmentMsg, new CmtPedersenDecommitmentMessage(new BigInteger(1, hashValArray), ((CmtPedersenDecommitmentMessage)decommitmentMsg).getR()));
		//If the inner Pedersen core algorithm returned null it means that it rejected the decommitment, so Pedersen Hash also rejects the answer and returns null
		if (val == null)
			return null;
		//The decommitment was accpeted by Pedersen core. Now, Pedersen Hash has to return the original value before the hashing.
		return new CmtByteArrayCommitValue(x);
	}
	
	/**
	 * This function converts the given commit value to a byte array. 
	 * @param value
	 * @return the generated bytes.
	 */
	public byte[] generateBytesFromCommitValue(CmtCommitValue value){
		if (!(value instanceof CmtByteArrayCommitValue))
			throw new IllegalArgumentException("The given value must be of type CmtByteArrayCommitValue");
		return (byte[]) value.getX();
	}

}