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

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.SigmaProverComputation;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.utility.SigmaProtocolInput;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.utility.SigmaProtocolMsg;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CommitValue;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.pedersenTrapdoor.PedersenTrapdoorCTReceiver;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.ReceiverCommitPhaseOutput;

/**
 * Concrete implementation of Zero Knowledge prover.
 * 
 * This is a transformation that takes any Sigma protocol and any perfectly hiding trapdoor (equivocal) 
 * commitment scheme and yields a zero-knowledge proof of knowledge.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class ZKPOKFromSigmaPedersenProver implements ZeroKnowledgeProver{

	private Channel channel;
	private SigmaProverComputation sProver; //Underlying prover that computes the proof of the sigma protocol.
	private PedersenTrapdoorCTReceiver receiver;		//Underlying Commitment receiver to use.
	
	
	
	/**
	 * Constructor that accepts the underlying channel, sigma protocol's prover.
	 * @param channel
	 * @param sProver
	 * @param receiver
	 */
	public ZKPOKFromSigmaPedersenProver(Channel channel, SigmaProverComputation sProver){
		
		this.sProver = sProver;
		this.receiver = new PedersenTrapdoorCTReceiver(channel);
		this.channel = channel;
	}
	
	/**
	 * Sets the input for this Zero Knowledge protocol.
	 * @param input must be an instance of SigmaProtocolInput.
	 * @throws IllegalArgumentException if the given input is not an instance of SigmaProtocolInput
	 */
	public void setInput(ZeroKnowledgeInput input){
		//The given input must be an instance of SigmaProtocolInput.
		if (!(input instanceof SigmaProtocolInput)){
			throw new IllegalArgumentException("the given input must be an instance of SigmaProtocolInput");
		}
		sProver.setInput((SigmaProtocolInput) input);
	}
	
	/**
	 * Runs the prover side of the Zero Knowledge proof.
	 * Let (a,e,z) denote the prover1, verifier challenge and prover2 messages of the sigma protocol.
	 * This function computes the following calculations:
	 *
	 *		 RUN the receiver in TRAP_COMMIT.commit; let trap be the output
	 * 		 COMPUTE the first message a in sigma, using (x,w) as input
	 *		 SEND a to V
	 *		 RUN the receiver in TRAP_COMMIT.decommit
	 *		 IF TRAP_COMMIT.decommit returns some e
     *		      COMPUTE the response z to (a,e) according to sigma
     *		      SEND z and trap to V
     *		      OUTPUT nothing
	 *		 ELSE (IF COMMIT.decommit returns INVALID)
     *			  OUTPUT ERROR (CHEAT_ATTEMPT_BY_V)
     *
	 * @throws IOException if failed to send the message.
	 * @throws CheatAttemptException if the challenge's length is not as expected. 
	 * @throws ClassNotFoundException 
	 */
	public void prove() throws IOException, CheatAttemptException, ClassNotFoundException {
		//Run the receiver in TRAP_COMMIT.commit 
		ReceiverCommitPhaseOutput trap = commit();
		//Compute the first message a in sigma, using (x,w) as input and 
		//Send a to V
		processFirstMsg();
		//Run the receiver in TRAP_COMMIT.decommit 
		//If decommit returns INVALID output ERROR (CHEAT_ATTEMPT_BY_V)
		byte[] e = decommit();
		//IF decommit returns some e, compute the response z to (a,e) according to sigma, 
	    //Send z to V and output nothing
		processSecondMsg(e, trap);
		
	}
	
	/**
	 * Runs the receiver in TRAP_COMMIT.commit with P as the receiver.
	 * @throws IOException 
	 * @throws ClassNotFoundException 
	 */
	private ReceiverCommitPhaseOutput commit() throws IOException, ClassNotFoundException{
		receiver.preProcess();
		return receiver.receiveCommitment();
	}

	/**
	 * Processes the first message of the Zero Knowledge protocol:
	 *  "COMPUTE the first message a in sigma, using (x,w) as input
	 *	SEND a to V".
	 * @throws IOException if failed to send the message.
	 */
	private void processFirstMsg() throws IOException{
		
		//Sample random values for the protocol by the underlying proverComputation.
		sProver.sampleRandomValues();
		//Compute the first message by the underlying proverComputation.
		SigmaProtocolMsg a = sProver.computeFirstMsg();
		//Send the first message.
		sendMsgToVerifier(a);
		
	}
	
	/**
	 * Runs the receiver in TRAP_COMMIT.decommit.
	 * If decommit returns INVALID output ERROR (CHEAT_ATTEMPT_BY_V)
	 * @param ctOutput
	 * @return
	 * @throws IOException 
	 * @throws CheatAttemptException if decommit phase returned invalid.
	 * @throws ClassNotFoundException 
	 */
	private byte[] decommit() throws IOException, CheatAttemptException, ClassNotFoundException{
		CommitValue val = receiver.receiveDecommitment(0);
		if (val == null){
			throw new CheatAttemptException("Decommit phase returned invalid");
		}
		return val.toByteArray();
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
	public void processSecondMsg(byte[] e, ReceiverCommitPhaseOutput trap) throws CheatAttemptException, IOException {
		
		//Compute the second message by the underlying proverComputation.
		SigmaProtocolMsg z = sProver.computeSecondMsg(e);
		
		//Send the second message.
		sendMsgToVerifier(z);
		
		//Send the trap.
		sendMsgToVerifier(trap);
		
	
	}
	
	/**
	 * Sends the given message to the verifier.
	 * @param message to send to the verifier.
	 * @throws IOException if failed to send the message.
	 */
	private void sendMsgToVerifier(Serializable message) throws IOException{
		try {
			//Send the message by the channel.
			channel.send(message);
		} catch (IOException e) {
			throw new IOException("failed to send the message. The thrown exception is: " + e.getMessage());
		}	
	}
}
