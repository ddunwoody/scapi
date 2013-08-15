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
import java.security.SecureRandom;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.exceptions.CommitValueException;
import edu.biu.scapi.exceptions.InvalidDlogGroupException;
import edu.biu.scapi.exceptions.SecurityLevelException;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.pedersenCommittedValue.SigmaPedersenCommittedValueProver;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.pedersenCommittedValue.SigmaPedersenCommittedValueProverInput;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.pedersen.PedersenCommitterCore;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.pedersenHash.PedersenHashCTCommitter;
import edu.biu.scapi.interactiveMidProtocols.zeroKnowledge.ZKFromSigmaProver;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.hash.CryptographicHash;

/**
 * Concrete implementation of equivocal commitment, with Pedersen hash commitment scheme.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class EquivocalPedersenHashCommitter extends EquivocalCTCommitter{

	/**
	 * Creates PedersenHash committer, and the corresponding sigma prover - PedersenCommittedValue.
	 * @param channel
	 * @param dlog
	 * @param t
	 * @param random
	 * @throws IllegalArgumentException
	 * @throws SecurityLevelException
	 * @throws InvalidDlogGroupException
	 */
	public EquivocalPedersenHashCommitter(Channel channel, DlogGroup dlog, CryptographicHash hash, int t, SecureRandom random) throws IllegalArgumentException, SecurityLevelException, InvalidDlogGroupException{
		super(channel, new PedersenHashCTCommitter(channel, dlog, hash), new ZKFromSigmaProver(channel, new SigmaPedersenCommittedValueProver(dlog, t, random)));
	}
	
	/**
	 * Default constructor that sets default values to the underlying committer and prover.
	 * @param channel
	 */
	public EquivocalPedersenHashCommitter(Channel channel){
		super(channel, new PedersenHashCTCommitter(channel), new ZKFromSigmaProver(channel, new SigmaPedersenCommittedValueProver()));
	}
	
	/**
	 * Runs the following line of the protocol:
	 * "Run ZK protocol as the prover, that x is the correct decommitment value".
	 * @throws IOException
	 * @throws CheatAttemptException
	 * @throws ClassNotFoundException
	 * @throws CommitValueException
	 */
	protected void runZK() throws IOException, CheatAttemptException, ClassNotFoundException, CommitValueException {
		//Create the input for the ZK prover
		SigmaPedersenCommittedValueProverInput input = ((PedersenCommitterCore) cTCommitter).getInputForZK();
		//Set the input
		prover.setInput(input);
		//Run the ZK prove protocol.
		prover.prove();
	}
}
