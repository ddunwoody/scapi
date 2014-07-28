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
import edu.biu.scapi.exceptions.CommitValueException;
import edu.biu.scapi.exceptions.SecurityLevelException;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.SigmaVerifierComputation;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaCommonInput;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaProtocolMsg;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCommitter;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCommitValue;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtOnBigInteger;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtOnByteArray;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.pedersen.CmtPedersenCommitter;
import edu.biu.scapi.securityLevel.PerfectlyHidingCmt;

/**
 * Concrete implementation of Zero Knowledge verifier.<p>
 * 
 * This is a transformation that takes any Sigma protocol and any perfectly hiding commitment scheme and 
 * yields a zero-knowledge proof.<p>
 * 
 * For more information see Protocol 6.5.1, page 161 of Hazay-Lindell.<p>
 * 
 * The pseudo code of this protocol can be found in Protocol 2.1 of pseudo codes document at {@link http://crypto.biu.ac.il/scapi/SDK_Pseudocode_SCAPI_V2.0.0.pdf}.<p>
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class ZKFromSigmaVerifier implements ZKVerifier{

	private Channel channel;
	private SigmaVerifierComputation sVerifier; //Underlying verifier that computes the proof of the sigma protocol.
	private CmtCommitter committer;				//Underlying Commitment committer to use.
	private SecureRandom random;
	
	/**
	 * Constructor that accepts the underlying channel, sigma protocol's verifier and committer to use.
	 * @param channel used to communicate between prover and verifier.
	 * @param sVerifier underlying sigma verifier to use.
	 * @param committer Must be an instance of PerfectlyHidingCT
	 * @throws SecurityLevelException if the given CTCommitter is not an instance of PerfectlyHidingCT
	 */
	public ZKFromSigmaVerifier(Channel channel, SigmaVerifierComputation sVerifier, CmtCommitter committer, SecureRandom random) throws SecurityLevelException{
		//committer must be an instance of PerfectlyHidingCT
		if (!(committer instanceof PerfectlyHidingCmt)){
			throw new SecurityLevelException("the given CTCommitter must be an instance of PerfectlyHidingCmt");
		}
		//committer must be an instance of PerfectlyHidingCT
		if (!(committer instanceof CmtOnBigInteger) && !(committer instanceof CmtOnByteArray)){
			throw new IllegalArgumentException("the given committer must be a commitment scheme on ByteArray or on BigInteger");
		}

		this.sVerifier = sVerifier;
		this.committer = committer;
		this.channel = channel;
		this.random = random;
	}
	
	/**
	 * Constructor that accepts the underlying channel, sigma protocol's verifier and sets default committer.
	 * @param channel used to communicate between prover and verifier.
	 * @param sVerifier underlying sigma verifier to use.
	 * @throws CheatAttemptException in case the verifier suspects the prover is trying to cheat.
	 * @throws IOException in case there was a problem in the communication.
	 * @throws ClassNotFoundException in case there was a problem in the serialization.
	 */
	public ZKFromSigmaVerifier(Channel channel, SigmaVerifierComputation sVerifier, SecureRandom random) throws ClassNotFoundException, IOException, CheatAttemptException{
	
		this.channel = channel;
		this.sVerifier = sVerifier;
		this.committer = new CmtPedersenCommitter(channel);
		this.random = random;
	}
	
	/**
	 * Runs the verifier side of the Zero Knowledge proof.<p>
	 * Let (a,e,z) denote the prover1, verifier challenge and prover2 messages of the sigma protocol.<p>
	 * This function computes the following calculations:<p>
	 *
	 *		 SAMPLE a random challenge  e <- {0, 1}^t <p>
	 *		 RUN COMMIT.commit as the committer with input e<p>
	 *		 WAIT for a message a from P<p>
	 *		 RUN COMMIT.decommit as the decommitter<p>
	 * 		 WAIT for a message z from P<p>
	 * 		 IF  transcript (a, e, z) is accepting in sigma on input x<p>
     *			OUTPUT ACC<p>
	 *		 ELSE<p>
     *	 	    OUTPUT REJ<p>
     * @param input must be an instance of SigmaCommonInput.
     * @throws IllegalArgumentException if the given input is not an instance of SigmaCommonInput
	 * @throws CheatAttemptException in case the verifier suspects the prover is trying to cheat.
	 * @throws IOException in case there was a problem in the communication.
	 * @throws ClassNotFoundException in case there was a problem in the serialization.
	 * @throws CommitValueException can occur in case the commitment scheme is ElGamal.
	 */
	public boolean verify(ZKCommonInput input) throws ClassNotFoundException, IOException, CheatAttemptException, CommitValueException {
		//The given input must be an instance of SigmaProtocolInput.
		if (!(input instanceof SigmaCommonInput)){
			throw new IllegalArgumentException("the given input must be an instance of SigmaCommonInput");
		}
		
		//Sample a random challenge  e <- {0, 1}^t 
		sVerifier.sampleChallenge();
		byte[] e = sVerifier.getChallenge();
		//Run COMMIT.commit as the committer with input e
		long id = commit(e);
		//Wait for a message a from P
		SigmaProtocolMsg a = receiveMsgFromProver();
		//Run COMMIT.decommit as the decommitter
		decommit(id);
		//Wait for a message z from P, 
		//If transcript (a, e, z) is accepting in sigma on input x, output ACC
		//Else outupt REJ
		return proccessVerify((SigmaCommonInput) input, a);
	}

	/**
	 * Runs COMMIT.commit as the committer with input e.
	 * @param e
	 * @throws CommitValueException 
	 * @throws IOException 
	 * @throws CheatAttemptException 
	 * @throws ClassNotFoundException 
	 */
	private long commit(byte[] e) throws IOException, ClassNotFoundException, CheatAttemptException, CommitValueException {
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
	 * Runs COMMIT.decommit as the decommitter.
	 * @param id 
	 * @throws IOException 
	 * @throws ClassNotFoundException 
	 * @throws CheatAttemptException 
	 * @throws CommitValueException 
	 */
	private void decommit(long id) throws IOException, CheatAttemptException, ClassNotFoundException, CommitValueException {
		committer.decommit(id);
		
	}
	
	/**
	 * Verifies the proof.
	 * @param input 
	 * @param a first message from prover.
	 * @throws IOException if failed to send the message.
	 * @throws ClassNotFoundException 
	 */
	private boolean proccessVerify(SigmaCommonInput input, SigmaProtocolMsg a) throws ClassNotFoundException, IOException {
		//Wait for a message z from P, 
		//If transcript (a, e, z) is accepting in sigma on input x, output ACC
		//Else outupt REJ
		
		SigmaProtocolMsg z = receiveMsgFromProver();
		return sVerifier.verify(input, a, z);
	}
}
