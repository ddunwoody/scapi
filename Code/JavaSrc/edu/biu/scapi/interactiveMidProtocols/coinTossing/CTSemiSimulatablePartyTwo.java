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
package edu.biu.scapi.interactiveMidProtocols.coinTossing;

import java.io.IOException;
import java.security.SecureRandom;

import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.exceptions.CommitValueException;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtByteArrayCommitValue;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCommitter;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtReceiver;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCommitValue;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtOnByteArray;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtRCommitPhaseOutput;
import edu.biu.scapi.securityLevel.OneSidedSimulation;
import edu.biu.scapi.securityLevel.PerfectlyBindingCmt;
import edu.biu.scapi.securityLevel.PerfectlyHidingCmt;

/**
 * This class plays as party two of coin tossing protocol which tosses a string.<p>
 * This protocol is fully secure (with simulation) when P1 is corrupted and fulfills a definition of “pseudorandomness” when P2 is corrupted. <p>
 * 
 * This protocol uses any perfectly-hiding commitment scheme (e.g., COMMIT_PEDERSEN,  COMMIT_HASH_PEDERSEN, COMMIT_HASH) 
 * and any perfectly-binding commitment scheme (e.g., COMMIT_ELGAMAL). <P>
 * 
 * The pseudo code of this protocol can be found in Protocol 6.3 of pseudo codes document at {@link http://crypto.biu.ac.il/scapi/SDK_Pseudocode_SCAPI_V2.0.0.pdf}.<p>
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class CTSemiSimulatablePartyTwo implements CTPartyTwo, OneSidedSimulation{

	private CmtReceiver receiver;
	private CmtCommitter committer;
	private int l;
	private SecureRandom random;
	
	/**
	 * Constructor that sets the given committer and receiver.
	 * @param committer MUST be a PerfectlyBinding secure.
	 * @param receiver MUST be a PerfectlyHiding secure.
	 * @param l determining the length of the output
	 * @param random
	 */
	public CTSemiSimulatablePartyTwo(CmtReceiver receiver, CmtCommitter committer, int l, SecureRandom random){
		if (!(receiver instanceof PerfectlyHidingCmt)){
			throw new IllegalArgumentException("The given receiver is not perfectly Hiding secure");
		}
		
		if (!(committer instanceof PerfectlyBindingCmt)){
			throw new IllegalArgumentException("The given committer is not perfectly Binding secure");
		}
		if (!(committer instanceof CmtOnByteArray)){
			throw new IllegalArgumentException("The given committer should work on a byte array input");
		}
		if (!(receiver instanceof CmtOnByteArray)){
			throw new IllegalArgumentException("The given receiver should work on a byte array input");
		}
		this.committer = committer;
		this.receiver = receiver;
		this.l = l;
		this.random = random;
	}

	/**
	 * Runs the following protocol:<p>
	 * "SAMPLE a random L-bit string s2 <- {0,1}^L<p>
	 *	RUN the receiver in subprotocol COMMIT_PERFECT_HIDING.commit <p>
	 *	RUN the committer in subprotocol COMMIT_PERFECT_BINDING.commit on s2<p>
	 *	RUN the receiver in subprotocol COMMIT_PERFECT_HIDING.decommit to receive s1<p>
	 *	RUN the committer in subprotocol COMMIT_PERFECT_BINDING.decommit to reveal s2<p>
	 *	OUTPUT s1 XOR s2"
	 */
	public CTOutput toss() throws ClassNotFoundException, IOException, CommitValueException, CheatAttemptException {
		//Sample a random L-bit string s2 <- {0,1}^L.
		byte[] s2 = new byte[l/8];
		random.nextBytes(s2);
		
		//Run the receiver in subprotocol COMMIT_PERFECT_HIDING.commit 
		CmtRCommitPhaseOutput output = receiver.receiveCommitment();
		
		//Run the committer in subprotocol COMMIT_PERFECT_BINDING.commit on s2
		CmtByteArrayCommitValue val = new CmtByteArrayCommitValue(s2);
		long id = random.nextLong();
		committer.commit(val, id);
		
		//Run the receiver in subprotocol COMMIT_PERFECT_HIDING.decommit to receive s1
		CmtCommitValue s1 = receiver.receiveDecommitment(output.getCommitmentId());
		
		//Run the committer in subprotocol COMMIT_PERFECT_BINDING.decommit to reveal s2
		committer.decommit(id);
		
		//Output s1 XOR s2.
		byte[] s1Bytes = receiver.generateBytesFromCommitValue(s1);
		if (s1Bytes.length != l/8){
			throw new IllegalArgumentException("The given s1 is not a L-bit string");
		}
		
		byte[] result = new byte[l/8];
		for (int i=0; i<l/8; i++){
			result[i] = (byte) (s1Bytes[i] ^ s2[i]);
		}
		//Return the output
		return new CTStringOutput(result);
	}
}
