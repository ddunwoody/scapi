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
package edu.biu.scapi.interactiveMidProtocols.sigmaProtocol;

import java.io.IOException;
import java.io.Serializable;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaCommonInput;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaProtocolMsg;

/**
 * This class manages the communication functionality of all the sigma protocol verifiers, 
 * such as send the challenge to the prover and receive the prover messages. <p>
 * It uses SigmaVerifierComputation instance of a concrete sigma protocol to compute the actual calculations. 
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class SigmaVerifier implements SigmaProtocolVerifier{
	
	/*
	 * This class manages the common functionality of all sigma verifiers:
	 * 	Verifier challenge (e):	SAMPLE a random challenge e
	 * 							RECEIVE first message from the prover
	 * 							SEND challenge to prover
	 * 	Verifier check:			RECEIVE second message from the prover
	 * 							VERIFY proof.     
	 */
	
	private Channel channel; 
	private SigmaVerifierComputation verifierComputation;
	private SigmaProtocolMsg a;	//First message from the prover.
	private boolean doneChallenge;
	
	/**
	 * Constructor that sets the given channel and random.
	 * @param channel
	 * @param random
	 */
	public SigmaVerifier(Channel channel, SigmaVerifierComputation verifierComputation){
		
		this.channel = channel;
		this.verifierComputation = verifierComputation;
		
	}
	
	/**
	 * Runs the verification of this protocol. <p>
	 * This function executes the verification protocol at once by calling the following functions one by one.<p>
	 * This function can be called when a user does not want to save time by doing operations in parallel.<p>
	 * @param input
	 * @return true if the proof has been verified; false, otherwise.
	 */
	public boolean verify(SigmaCommonInput input) throws ClassNotFoundException, IOException{
		//Samples the challenge.
		sampleChallenge();
		//Sends the challenge.
		sendChallenge();
		//Verifies the proof.
		return processVerify(input);
	}
	
	/**
	 * Runs the challenge sampling from the protocol.<p>
	 * "SAMPLE a random challenge e".
	 */
	public void sampleChallenge(){
		//Delegates to the underlying verifierComputation object.
		verifierComputation.sampleChallenge();
	}
	
	/**
	 * Sets the given challenge.
	 * @param challenge
	 */
	public void setChallenge(byte[] challenge){
		//Delegates to the underlying verifierComputation object.
		verifierComputation.setChallenge(challenge);
	}
	
	/**
	 * Returns the sampled challenge.
	 * @return the challenge.
	 */
	public byte[] getChallenge(){
		//Delegates to the underlying verifierComputation object.
		return verifierComputation.getChallenge();
	}
	
	/**
	 * Receive message from the prover and sends the challenge.<p>
	 * Runs the following lines from the protocol:<p>
	 * 	"RECEIVE first message from the prover.<p>
	 * 	 SEND challenge to prover".<p>
	 * This is a blocking function!
	 * @throws IOException if failed to send or receive a message.
	 * @throws ClassNotFoundException
	 */
	public void sendChallenge() throws IOException, ClassNotFoundException{
		
		//Wait for first message from the prover.
		a = receiveMsgFromProver();
		
		//get the challenge from the verifierComputation.
		byte[] challenge = verifierComputation.getChallenge();
		if (challenge == null){
			throw new IllegalStateException("sampleChallenge function should be called before sendChallenge");
		}
		//Send the challenge.
		sendChallengeToProver(challenge);
		
		//Save the state of the protocol.
		doneChallenge = true;
		
	}

	/**
	 * Receive message from the prover and verify the proof.<p>
	 * Runs the following lines from the protocol:<p>
	 * 	"RECEIVE second message from the prover<p>
	 * 	 VERIFY proof".	<p>
	 * This is a blocking function!
	 * @param input
	 * @return true if the proof has been verified; false, otherwise.
	 * @throws IOException if failed to receive a message.
	 * @throws ClassNotFoundException
	 */
	public boolean processVerify(SigmaCommonInput input) throws ClassNotFoundException, IOException{
		if (!doneChallenge){
			throw new IllegalStateException("sampleChallenge and sendChallenge should be called before processVerify");
		}

		//Wait for second message from the prover.
		SigmaProtocolMsg z = receiveMsgFromProver();
		//Verify the proof
		boolean verified = verifierComputation.verify(input, a, z);
		
		//Save the state of the protocol.
		doneChallenge = false;
		
		return verified;
	}

	/**
	 * Waits for message from receiver and returns it.
	 * @return the received message. MUST be an instance of SigmaProtocolMsg.
	 * @throws ClassNotFoundException 
	 * @throws IOException if failed to receive a message.
	 * @throws IllegalArgumentException if the received message is not an instance of SigmaProtocolMsg.
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
	 * Sends the challenge to the prover.
	 * @throws IOException if failed to send the challenge.
	 */
	private void sendChallengeToProver(byte[] challenge) throws IOException {
	
		try {
			//Send the challenge by the channel.
			channel.send(challenge);
		} catch (IOException e) {
			throw new IOException("failed to send the message. The thrown message is: " + e.getMessage());
		}	
		
	}

}
