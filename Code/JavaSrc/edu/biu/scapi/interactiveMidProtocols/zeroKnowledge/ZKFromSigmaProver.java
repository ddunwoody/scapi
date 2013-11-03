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

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.exceptions.CommitValueException;
import edu.biu.scapi.exceptions.SecurityLevelException;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.SigmaProverComputation;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.utility.SigmaProtocolMsg;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.utility.SigmaProverInput;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CTReceiver;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CommitValue;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.OnBigIntegerCommitmentScheme;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.OnByteArrayCommitmentScheme;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.ReceiverCommitPhaseOutput;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.pedersen.PedersenCTReceiver;
import edu.biu.scapi.securityLevel.PerfectlyHidingCT;

/**
 * Concrete implementation of Zero Knowledge prover.
 * 
 * This is a transformation that takes any Sigma protocol and any perfectly hiding commitment scheme and 
 * yields a zero-knowledge proof.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class ZKFromSigmaProver implements ZKProver{

	private Channel channel;
	private SigmaProverComputation sProver; //Underlying prover that computes the proof of the sigma protocol.
	private CTReceiver receiver;			//Underlying Commitment receiver to use.
	
	/**
	 * Constructor that accepts the underlying channel, sigma protocol's prover and commitment's receiver to use.
	 * @param channel
	 * @param sProver
	 * @param receiver
	 * @throws SecurityLevelException if the given CTReceiver is not an instance of PerfectlyHidingCT
	 */
	public ZKFromSigmaProver(Channel channel, SigmaProverComputation sProver, CTReceiver receiver) throws SecurityLevelException{
		//receiver must be an instance of PerfectlyHidingCT
		if (!(receiver instanceof PerfectlyHidingCT)){
			throw new SecurityLevelException("the given CTReceiver must be an instance of PerfectlyHidingCT");
		}
		//receiver must be a commitment scheme on ByteArray or on BigInteger
		if (!(receiver instanceof OnBigIntegerCommitmentScheme) && !(receiver instanceof OnByteArrayCommitmentScheme)){
			throw new IllegalArgumentException("the given CTReceiver must be a commitment scheme on ByteArray or on BigInteger");
		}

		this.sProver = sProver;
		this.receiver = receiver;
		this.channel = channel;
	}
	
	/**
	 * Constructor that accepts the underlying channel, sigma protocol's prover and sets default commitment's receiver.
	 * @param channel
	 * @param sProver
	 * @throws IOException can be thrown in the pre-process stage of PedersenCTReceiver
	 */
	public ZKFromSigmaProver(Channel channel, SigmaProverComputation sProver) throws IOException{
		
		this.sProver = sProver;
		this.receiver = new PedersenCTReceiver(channel);
		this.channel = channel;
	}
	
	/**
	 * Runs the prover side of the Zero Knowledge proof.
	 * Let (a,e,z) denote the prover1, verifier challenge and prover2 messages of the sigma protocol.
	 * This function computes the following calculations:
	 *
	 *		 RUN the receiver in COMMIT.commit 
	 *		 COMPUTE the first message a in sigma, using (x,w) as input
	 *		 SEND a to V
	 *		 RUN the receiver in COMMIT.decommit 
	 *			IF COMMIT.decommit returns some e
     *     			COMPUTE the response z to (a,e) according to sigma
     *      		SEND z to V
     *      		OUTPUT nothing
	 *			ELSE (IF COMMIT.decommit returns INVALID)
     *      		OUTPUT ERROR (CHEAT_ATTEMPT_BY_V)
     * @param input must be an instance of SigmaProverInput.
     * @throws IllegalArgumentException if the given input is not an instance of SigmaProverInput
	 * @throws IOException if failed to send the message.
	 * @throws CheatAttemptException if the challenge's length is not as expected. 
	 * @throws ClassNotFoundException 
	 * @throws CommitValueException 
	 */
	public void prove(ZKProverInput input) throws IOException, CheatAttemptException, ClassNotFoundException, CommitValueException {
		//The given input must be an instance of SigmaProtocolInput.
		if (!(input instanceof SigmaProverInput)){
			throw new IllegalArgumentException("the given input must be an instance of SigmaProverInput");
		}
				
		//Run the receiver in COMMIT.commit 
		ReceiverCommitPhaseOutput output = receiveCommit();
		//Compute the first message a in sigma, using (x,w) as input and 
		//Send a to V
		processFirstMsg((SigmaProverInput) input);
		//Run the receiver in COMMIT.decommit 
		//If decommit returns INVALID output ERROR (CHEAT_ATTEMPT_BY_V)
		byte[] e = receiveDecommit(output.getCommitmentId());
		//IF decommit returns some e, compute the response z to (a,e) according to sigma, 
	    //Send z to V and output nothing
		processSecondMsg(e);
		
	}
	
	/**
	 * Runs the receiver in COMMIT.commit with P as the receiver.
	 * @throws IOException 
	 * @throws ClassNotFoundException 
	 */
	private ReceiverCommitPhaseOutput receiveCommit() throws IOException, ClassNotFoundException{
		return receiver.receiveCommitment();
	}

	/**
	 * Processes the first message of the Zero Knowledge protocol:
	 *  "COMPUTE the first message a in sigma, using (x,w) as input
	 *	SEND a to V".
	 * @param input 
	 * @throws IOException if failed to send the message.
	 */
	private void processFirstMsg(SigmaProverInput input) throws IOException{
		
		//Compute the first message by the underlying proverComputation.
		SigmaProtocolMsg a = sProver.computeFirstMsg(input);
		//Send the first message.
		sendMsgToVerifier(a);
		
	}
	
	/**
	 * Runs the receiver in COMMIT.decommit
	 * If decommit returns INVALID output ERROR (CHEAT_ATTEMPT_BY_V)
	 * @param l 
	 * @param ctOutput
	 * @return
	 * @throws IOException 
	 * @throws CheatAttemptException if decommit phase returned invalid.
	 * @throws ClassNotFoundException 
	 * @throws CommitValueException 
	 */
	private byte[] receiveDecommit(long id) throws IOException, CheatAttemptException, ClassNotFoundException, CommitValueException{
		CommitValue val = receiver.receiveDecommitment(id);
		if (val == null){
			throw new CheatAttemptException("Decommit phase returned invalid");
		}
		return receiver.generateBytesFromCommitValue(val);
	}
	
	/**
	 * Processes the second message of the Zero Knowledge protocol:
	 * 	"COMPUTE the response z to (a,e) according to sigma
     *   SEND z to V
     *   OUTPUT nothing".
	 * This is a blocking function!
	 * @throws CheatAttemptException if the challenge's length is not as expected.
	 * @throws IOException if failed to send the message.
	 */
	public void processSecondMsg(byte[] e) throws CheatAttemptException, IOException {
		
		//Compute the second message by the underlying proverComputation.
		SigmaProtocolMsg z = sProver.computeSecondMsg(e);
		
		//Send the second message.
		sendMsgToVerifier(z);
	
	}
	
	/**
	 * Sends the given message to the verifier.
	 * @param message to send to the verifier.
	 * @throws IOException if failed to send the message.
	 */
	private void sendMsgToVerifier(SigmaProtocolMsg message) throws IOException{
		try {
			//Send the message by the channel.
			channel.send(message);
		} catch (IOException e) {
			throw new IOException("failed to send the message. The thrown exception is: " + e.getMessage());
		}	
	}
}
