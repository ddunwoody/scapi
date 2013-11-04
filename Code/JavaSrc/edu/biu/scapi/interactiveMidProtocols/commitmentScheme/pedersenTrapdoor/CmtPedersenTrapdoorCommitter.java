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

import org.bouncycastle.util.BigIntegers;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.exceptions.InvalidDlogGroupException;
import edu.biu.scapi.exceptions.SecurityLevelException;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.BigIntegerCommitValue;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CTCommitter;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CommitValue;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.OnBigIntegerCommitmentScheme;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.ReceiverCommitPhaseOutput;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.TrapdoorReceiverCommitPhaseOutput;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.pedersen.PedersenCommitterCore;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.securityLevel.PerfectlyHidingCT;

/**
 * Concrete implementation of committer that executes the Pedersen trapdoor commitment 
 * scheme in the committer's point of view.
 * This commitment is also a trapdoor commitment in the sense that the receiver after 
 * the commitment phase has a trapdoor value, that if known by the committer would enable
 * it to decommit to any value. 
 * This trapdoor is output by the receiver and can be used by a higher-level application 
 * (e.g., by the ZK transformation of a sigma protocol to a zero-knowledge proof of knowledge).
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class PedersenTrapdoorCTCommitter extends PedersenCommitterCore implements  CTCommitter, PerfectlyHidingCT, OnBigIntegerCommitmentScheme{

	/**
	 * Constructor that receives a connected channel (to the receiver) and chooses default dlog and random. 
	 * The receiver needs to be instantiated with the default constructor too.
	 * @param channel
	 * @throws ClassNotFoundException in case there was a problem in the serialization in the preprocess phase.
	 * @throws IOException in case there was a problem in the communication in the preprocess phase.
	 * @throws CheatAttemptException in case the committer suspects the receiver cheated in the preprocess phase.
	 */
	public PedersenTrapdoorCTCommitter(Channel channel) throws ClassNotFoundException, IOException, CheatAttemptException{
		super(channel);
	}
	
	/**
	 * Constructor that receives a connected channel (to the receiver), the DlogGroup agreed upon between them and a SecureRandom object.
	 * The Receiver needs to be instantiated with the same DlogGroup, otherwise nothing will work properly.
	 * @param channel
	 * @param dlog
	 * @param random
	 * @throws SecurityLevelException if the given dlog is not DDH secure
	 * @throws InvalidDlogGroupException if the given dlog is not valid.
	 * @throws ClassNotFoundException if there was a problem in the serialization
	 * @throws IOException if there was a problem in the communication
	 * @throws CheatAttemptException if the receiver h is not in the DlogGroup.
	 */
	public PedersenTrapdoorCTCommitter(Channel channel, DlogGroup dlog, SecureRandom random) throws IllegalArgumentException, SecurityLevelException, InvalidDlogGroupException, ClassNotFoundException, IOException, CheatAttemptException{
		super(channel, dlog, random);
	}

	/**
	 * This function samples random commit value and returns it.
	 * @return the sampled commit value
	 */
	public CommitValue sampleRandomCommitValue(){
		BigInteger qMinusOne = dlog.getOrder().subtract(BigInteger.ONE);
		BigInteger val = BigIntegers.createRandomInRange(BigInteger.ZERO, qMinusOne, random);
		return new BigIntegerCommitValue(val);
	}
	
	@Override
	public CommitValue generateCommitValue(byte[] x)  {
		return new BigIntegerCommitValue(new BigInteger(x));
	}
	
	/**
	 * This function converts the given commit value to a byte array. 
	 * @param value
	 * @return the generated bytes.
	 */
	public byte[] generateBytesFromCommitValue(CommitValue value){
		if (!(value instanceof BigIntegerCommitValue))
			throw new IllegalArgumentException("The given value must be of type BigIntegerCommitValue");
		return ((BigInteger)value.getX()).toByteArray();
	}
	
	/**
	 * Validate the h value received from the receiver in the pre process phase.
	 * @param trap
	 * @return true, if valif; false, otherwise.
	 */
	public boolean validate(ReceiverCommitPhaseOutput trap){
		if (!(trap instanceof TrapdoorReceiverCommitPhaseOutput)){
			throw new IllegalArgumentException("the given trapdor should be an instance of TrapdoorReceiverCommitPhaseOutput");
		}
		
		//Check that g^trapdoor equals to h.
		TrapdoorReceiverCommitPhaseOutput trapdoor = (TrapdoorReceiverCommitPhaseOutput) trap;
		GroupElement gToTrap = dlog.exponentiate(dlog.getGenerator(), trapdoor.getTrap());
		
		if (gToTrap.equals(h)){
			return true;
		}
		return false;
	}
}
