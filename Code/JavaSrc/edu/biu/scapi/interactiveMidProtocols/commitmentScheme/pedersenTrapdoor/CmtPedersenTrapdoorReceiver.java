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
package edu.biu.scapi.interactiveMidProtocols.commitmentScheme.pedersenTrapdoor;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.InvalidDlogGroupException;
import edu.biu.scapi.exceptions.SecurityLevelException;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtRBasicCommitPhaseOutput;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtBigIntegerCommitValue;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtReceiver;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCommitValue;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtOnBigInteger;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtRTrapdoorCommitPhaseOutput;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.pedersen.CmtPedersenReceiverCore;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.securityLevel.PerfectlyHidingCmt;

/**
 * Concrete implementation of receiver that executes the Pedersen trapdoor commitment 
 * scheme in the receiver's point of view.
 * 
 * This commitment is also a trapdoor commitment in the sense that the receiver after 
 * the commitment phase has a trapdoor value, that if known by the committer would enable
 * it to decommit to any value. 
 * This trapdoor is output by the receiver and can be used by a higher-level application 
 * (e.g., by the ZK transformation of a sigma protocol to a zero-knowledge proof of knowledge).
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class CmtPedersenTrapdoorReceiver extends CmtPedersenReceiverCore implements  CmtReceiver, PerfectlyHidingCmt, CmtOnBigInteger {
	
	/**
	 * Constructor that receives a connected channel (to the receiver) and chooses default dlog and random. 
	 * The committer needs to be instantiated with the default constructor too.
	 * @param channel
	 * @throws IOException in case there was a problem in the communication in the preprocess phase.
	 */
	public CmtPedersenTrapdoorReceiver(Channel channel) throws IOException	 {
		super(channel);
	}
	
	/**
	 * Constructor that receives a connected channel (to the receiver), the DlogGroup agreed upon between them and a SecureRandom object.
	 * The committer needs to be instantiated with the same DlogGroup, otherwise nothing will work properly.
	 * @param channel
	 * @param dlog
	 * @param random
	 * @throws SecurityLevelException if the given dlog is not DDH secure
	 * @throws InvalidDlogGroupException if the given dlog is not valid.
	 * @throws IOException if there was a problem in the communication
	 */
	public CmtPedersenTrapdoorReceiver(Channel channel, DlogGroup dlog, SecureRandom random) throws SecurityLevelException, InvalidDlogGroupException, IOException{
		super(channel, dlog, random);
	}

	/**
	 * Returns the receiver's trapdoor from the preprocess phase.
	 * @return
	 */
	public BigInteger getTrapdoor(){
		return trapdoor;
	}
	
	@Override
	public CmtRBasicCommitPhaseOutput receiveCommitment() throws ClassNotFoundException, IOException {
		//Get the output from the super.receiverCommiotment.
		CmtRBasicCommitPhaseOutput output = super.receiveCommitment();
		
		//Wrap the output with the trapdoor.
		return new CmtRTrapdoorCommitPhaseOutput(trapdoor, output.getCommitmentId());
	}
	
	/**
	 * This function converts the given commit value to a byte array. 
	 * @param value
	 * @return the generated bytes.
	 */
	public byte[] generateBytesFromCommitValue(CmtCommitValue value){
		if (!(value instanceof CmtBigIntegerCommitValue))
			throw new IllegalArgumentException("The given value must be of type CmtBigIntegerCommitValue");
		//Remove the first byte of BigInteger in order to get the original x.
		byte[] biBytes = ((BigInteger)value.getX()).toByteArray();
		byte[] x = new byte[biBytes.length - 1];
		System.arraycopy(biBytes, 1, x, 0, biBytes.length - 1);
		return x;
	}
}