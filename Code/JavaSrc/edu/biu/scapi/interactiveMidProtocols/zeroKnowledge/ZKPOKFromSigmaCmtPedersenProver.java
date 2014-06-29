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
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.SigmaProverComputation;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaProtocolMsg;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaProverInput;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCommitValue;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.pedersenTrapdoor.CmtPedersenTrapdoorReceiver;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtRCommitPhaseOutput;

/**
 * Concrete implementation of Zero Knowledge prover.<p>
 * 
 * This is a transformation that takes any Sigma protocol and any perfectly hiding trapdoor (equivocal) 
 * commitment scheme and yields a zero-knowledge proof of knowledge.<p>
 * 
 * For more information see Protocol 6.5.4, page 165 of Hazay-Lindell.<p>
 * 
 * The pseudo code of this protocol can be found in Protocol 2.2 of pseudo codes document at {@link http://crypto.biu.ac.il/scapi/SDK_Pseudocode_SCAPI_V2.0.0.pdf}.<p>
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class ZKPOKFromSigmaCmtPedersenProver implements ZKPOKProver{

	private Channel channel;
	private SigmaProverComputation sProver; //Underlying prover that computes the proof of the sigma protocol.
	private CmtPedersenTrapdoorReceiver receiver;		//Underlying Commitment receiver to use.
	
	
	
	/**
	 * Constructor that accepts the underlying channel and sigma protocol's prover.
	 * @param channel used for communication
	 * @param sProver underlying sigma prover to use.
	 * @throws IOException if there was a problem to create the receiver.
	 */
	public ZKPOKFromSigmaCmtPedersenProver(Channel channel, SigmaProverComputation sProver) throws IOException{
		
		this.sProver = sProver;
		this.receiver = new CmtPedersenTrapdoorReceiver(channel);
		this.channel = channel;
	}
	
	/**
	 * Runs the prover side of the Zero Knowledge proof.<p>
	 * Let (a,e,z) denote the prover1, verifier challenge and prover2 messages of the sigma protocol.<p>
	 * This function computes the following calculations:<p>
	 *
	 *		 RUN the receiver in TRAP_COMMIT.commit; let trap be the output<p>
	 * 		 COMPUTE the first message a in sigma, using (x,w) as input<p>
	 *		 SEND a to V<p>
	 *		 RUN the receiver in TRAP_COMMIT.decommit<p>
	 *		 IF TRAP_COMMIT.decommit returns some e<p>
     *		      COMPUTE the response z to (a,e) according to sigma<p>
     *		      SEND z and trap to V<p>
     *		      OUTPUT nothing<p>
	 *		 ELSE (IF COMMIT.decommit returns INVALID)<p>
     *			  OUTPUT ERROR (CHEAT_ATTEMPT_BY_V)<p>
     *
     * @param input must be an instance of SigmaProverInput.
     * @throws IllegalArgumentException if the given input is not an instance of SigmaProverInput
	 * @throws IOException if failed to send the message.
	 * @throws CheatAttemptException if the challenge's length is not as expected. 
	 * @throws ClassNotFoundException if there was a problem with the serialization mechanism.
	 */
	public void prove(ZKProverInput input) throws IOException, CheatAttemptException, ClassNotFoundException {
		//The given input must be an instance of SigmaProtocolInput.
		if (!(input instanceof SigmaProverInput)){
			throw new IllegalArgumentException("the given input must be an instance of SigmaProverInput");
		}
				
		//Run the receiver in TRAP_COMMIT.commit 
		CmtRCommitPhaseOutput trap = receiveCommit();
		//Compute the first message a in sigma, using (x,w) as input and 
		//Send a to V
		processFirstMsg((SigmaProverInput) input);
		//Run the receiver in TRAP_COMMIT.decommit 
		//If decommit returns INVALID output ERROR (CHEAT_ATTEMPT_BY_V)
		byte[] e = receiveDecommit(trap.getCommitmentId());
		//IF decommit returns some e, compute the response z to (a,e) according to sigma, 
	    //Send z to V and output nothing
		processSecondMsg(e, trap);
		
	}
	
	/**
	 * Runs the receiver in TRAP_COMMIT.commit with P as the receiver.
	 * @throws IOException 
	 * @throws ClassNotFoundException 
	 */
	private CmtRCommitPhaseOutput receiveCommit() throws IOException, ClassNotFoundException{
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
	 * Runs the receiver in TRAP_COMMIT.decommit.
	 * If decommit returns INVALID output ERROR (CHEAT_ATTEMPT_BY_V)
	 * @param id 
	 * @param ctOutput
	 * @return
	 * @throws IOException 
	 * @throws CheatAttemptException if decommit phase returned invalid.
	 * @throws ClassNotFoundException 
	 */
	private byte[] receiveDecommit(long id) throws IOException, CheatAttemptException, ClassNotFoundException{
		CmtCommitValue val = receiver.receiveDecommitment(id);
		if (val == null){
			throw new CheatAttemptException("Decommit phase returned invalid");
		}
		return receiver.generateBytesFromCommitValue(val);
	}
	
	/**
	 * Processes the second message of the Zero Knowledge protocol.<p>
	 * 	"COMPUTE the response z to (a,e) according to sigma<p>
     *   SEND z to V<p>
     *   OUTPUT nothing".<p>
	 * This is a blocking function!
	 * @throws CheatAttemptException if the challenge's length is not as expected.
	 * @throws IOException if failed to send the message.
	 */
	public void processSecondMsg(byte[] e, CmtRCommitPhaseOutput trap) throws CheatAttemptException, IOException {
		
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
