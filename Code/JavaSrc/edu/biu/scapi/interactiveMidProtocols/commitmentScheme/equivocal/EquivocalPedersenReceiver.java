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
package edu.biu.scapi.interactiveMidProtocols.commitmentScheme.equivocal;

import java.io.IOException;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.SecureRandom;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.exceptions.CommitValueException;
import edu.biu.scapi.exceptions.InvalidDlogGroupException;
import edu.biu.scapi.exceptions.SecurityLevelException;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.pedersenCommittedValue.SigmaPedersenCommittedValueInput;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.pedersenCommittedValue.SigmaPedersenCommittedValueVerifier;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.BigIntegerCommitValue;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CommitValue;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.pedersen.PedersenCTReceiver;
import edu.biu.scapi.interactiveMidProtocols.zeroKnowledge.ZKFromSigmaVerifier;
import edu.biu.scapi.primitives.dlog.DlogGroup;

/**
 * Concrete implementation of equivocal commitment, with Pedersen commitment scheme.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class EquivocalPedersenReceiver extends EquivocalCTReceiver{
	
	/**
	 * Creates Pedersen receiver, and the corresponding sigma verifier - PedersenCommittedValue.
	 * @param channel
	 * @param dlog
	 * @param t
	 * @param random
	 * @throws IllegalArgumentException
	 * @throws SecurityLevelException
	 * @throws InvalidDlogGroupException
	 */
	public EquivocalPedersenReceiver(Channel channel, DlogGroup dlog, int t, SecureRandom random) throws IllegalArgumentException, SecurityLevelException, InvalidDlogGroupException{
		super(channel, new PedersenCTReceiver(channel, dlog), new ZKFromSigmaVerifier(channel, new SigmaPedersenCommittedValueVerifier(dlog, t, random)));
	}
	
	/**
	 * Default constructor that sets default values to the underlying receiver and verifier.
	 * @param channel
	 */
	public EquivocalPedersenReceiver(Channel channel){
		super(channel, new PedersenCTReceiver(channel), new ZKFromSigmaVerifier(channel, new SigmaPedersenCommittedValueVerifier()));
	}
	
	/**
	 * Runs the underlying ZK protocol.
	 */
	protected void runZK(CommitValue x) throws IOException, ClassNotFoundException, CommitValueException, CheatAttemptException {
		//Create the input for the ZK receiver
		SigmaPedersenCommittedValueInput input = ((PedersenCTReceiver)cTReceiver).getInputForZK((BigInteger) x.getX());
		//Set the input
		verifier.setInput(input);
		//Run the ZK verify protocol.
		verifier.verify();
		
	}

	/**
	 * receives the message from the committer.
	 */
	protected CommitValue waitForMsgFromCommitter() throws ClassNotFoundException, IOException {
		Serializable x = null;
		try{
			x = channel.receive();
		} catch (ClassNotFoundException e) {
			throw new ClassNotFoundException("Failed to receive commitment. The error is: " + e.getMessage());
		} catch (IOException e) {
			throw new IOException("Failed to receive commitment. The error is: " + e.getMessage());
		}
		//The commitment value in this protocol should be instance of BigInteger.
		if (!(x instanceof BigInteger)){
			throw new IllegalArgumentException("x Should be an instance of BigInteger");
		}
		return new BigIntegerCommitValue((BigInteger) x);
	}

}
