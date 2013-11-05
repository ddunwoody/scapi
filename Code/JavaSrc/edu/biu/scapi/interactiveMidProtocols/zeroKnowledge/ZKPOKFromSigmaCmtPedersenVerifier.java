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
package edu.biu.scapi.interactiveMidProtocols.zeroKnowledge;

import java.io.IOException;
import java.io.Serializable;
import java.security.SecureRandom;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.SigmaVerifierComputation;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaCommonInput;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaProtocolMsg;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCommitValue;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtRCommitPhaseOutput;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.pedersenTrapdoor.CmtPedersenTrapdoorCommitter;

/**
 * Concrete implementation of Zero Knowledge verifier.
 * 
 * This is a transformation that takes any Sigma protocol and any perfectly hiding trapdoor (equivocal) 
 * commitment scheme and yields a zero-knowledge proof of knowledge.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class ZKPOKFromSigmaCmtPedersenVerifier implements ZKPOKVerifier{

	private Channel channel;
	private SigmaVerifierComputation sVerifier; //Underlying verifier that computes the proof of the sigma protocol.
	private CmtPedersenTrapdoorCommitter committer;				//Underlying Commitment committer to use.
	private SecureRandom random;
	
	
	/**
	 * Constructor that accepts the underlying channel, sigma protocol's verifier.
	 * @param channel
	 * @param sVerifier
	 * @throws CheatAttemptException 
	 * @throws IOException 
	 * @throws ClassNotFoundException 
	 */
	public ZKPOKFromSigmaCmtPedersenVerifier(Channel channel, SigmaVerifierComputation sVerifier, SecureRandom random) throws ClassNotFoundException, IOException, CheatAttemptException{
	
		this.channel = channel;
		this.sVerifier = sVerifier;
		this.committer = new CmtPedersenTrapdoorCommitter(channel);
		this.random = random;
	}
	
	/**
	 * Runs the verifier side of the Zero Knowledge proof.
	 * Let (a,e,z) denote the prover1, verifier challenge and prover2 messages of the sigma protocol.
	 * This function computes the following calculations:
	 *
	 *		 SAMPLE a random challenge  e <- {0, 1^t 
	 *		 RUN TRAP_COMMIT.commit as the committer with input e
	 *		 WAIT for a message a from P
	 *		 RUN TRAP_COMMIT.decommit as the decommitter
	 *		 WAIT for a message (z,trap) from P
	 *		 IF  
	 *			•	TRAP_COMMIT.valid(T,trap) = 1, where T  is the transcript from the commit phase, AND
	 *			•	Transcript (a, e, z) is accepting in sigma on input x
	 *          OUTPUT ACC
	 *       ELSE 	
	 *          OUTPUT REJ

	 * @param input must be an instance of SigmaCommonInput.
	 * @throws IllegalArgumentException if the given input is not an instance of SigmaCommonInput
	 * @throws IOException if failed to send the message.
	 * @throws ClassNotFoundException 
	 * @throws CheatAttemptException 
	 */
	public boolean verify(ZKCommonInput input) throws ClassNotFoundException, IOException, CheatAttemptException{
		//The given input must be an instance of SigmaProtocolInput.
		if (!(input instanceof SigmaCommonInput)){
			throw new IllegalArgumentException("the given input must be an instance of SigmaCommonInput");
		}
				
		//Sample a random challenge  e <- {0, 1}^t 
		sVerifier.sampleChallenge();
		byte[] e = sVerifier.getChallenge();
		
		//Run TRAP_COMMIT.commit as the committer with input e,
		long id = commit(e);
		//Wait for a message a from P
		SigmaProtocolMsg a = receiveMsgFromProver();
		
		//Run COMMIT.decommit as the decommitter
		committer.decommit(id);
		
		boolean valid = true;
		
		//Wait for a message z from P
		SigmaProtocolMsg z = receiveMsgFromProver();
		//Wait for trap from P
		CmtRCommitPhaseOutput trap = receiveTrapFromProver();
		
		//Run TRAP_COMMIT.valid(T,trap), where T is the transcript from the commit phase
		valid = valid && committer.validate(trap);
		
		//Run transcript (a, e, z) is accepting in sigma on input x
		valid = valid && proccessVerify((SigmaCommonInput) input, a, z);
		
		//If decommit and sigma verify returned true, return ACCEPT. Else, return REJECT.
		return valid;
	}

	/**
	 * Runs COMMIT.commit as the committer with input e.
	 * @param e
	 * @throws IOException 
	 * @throws CheatAttemptException 
	 * @throws ClassNotFoundException 
	 */
	private long commit(byte[] e) throws IOException, ClassNotFoundException, CheatAttemptException {
		
		CmtCommitValue val = committer.generateCommitValue(e);
		long id = random.nextLong();
		committer.commit(val, id);
		return id;
		
	}
	
	/**
	 * Waits for a message a from the prover.
	 * @return the received message
	 * @throws ClassNotFoundException
	 * @throws IOException if failed to send the message.
	 */
	private SigmaProtocolMsg receiveMsgFromProver() throws ClassNotFoundException, IOException {
		Serializable msg = null;
		try {
			//receive the mesage.
			msg = channel.receive();
		} catch (IOException e) {
			throw new IOException("failed to receive the a message. The thrown message is: " + e.getMessage());
		}
		//If the given message is not an instance of SigmaProtocolMsg, throw exception.
		if (!(msg instanceof SigmaProtocolMsg)){
			throw new IllegalArgumentException("the given message should be an instance of SigmaProtocolMsg");
		}
		//Return the given message.
		return (SigmaProtocolMsg) msg;
	}
	
	/**
	 * Waits for a trapdoor a from the prover.
	 * @return the received message
	 * @throws ClassNotFoundException
	 * @throws IOException if failed to send the message.
	 */
	private CmtRCommitPhaseOutput receiveTrapFromProver() throws ClassNotFoundException, IOException {
		Serializable msg = null;
		try {
			//receive the mesage.
			msg = channel.receive();
		} catch (IOException e) {
			throw new IOException("failed to receive the a message. The thrown message is: " + e.getMessage());
		}
		//If the given message is not an instance of ReceiverCommitPhaseOutput, throw exception.
		if (!(msg instanceof CmtRCommitPhaseOutput)){
			throw new IllegalArgumentException("the given message should be an instance of CmtRCommitPhaseOutput");
		}
		//Return the given message.
		return (CmtRCommitPhaseOutput) msg;
	}
	
	/**
	 * Verifies the proof.
	 * @param input 
	 * @param a first message from prover.
	 * @param z second message from prover.
	 */
	private boolean proccessVerify(SigmaCommonInput input, SigmaProtocolMsg a, SigmaProtocolMsg z){
		
		//Run transcript (a, e, z) is accepting in sigma on input x
		return sVerifier.verify(input, a, z);
	}

}
