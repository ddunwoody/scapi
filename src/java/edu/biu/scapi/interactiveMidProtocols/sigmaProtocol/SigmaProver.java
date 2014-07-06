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
import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaProverInput;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaProtocolMsg;

/**
 * This class manages the communication functionality of all the sigma protocol provers.<p>
 * It sends the first message, receives the challenge from the prover and sends the second message.<p>
 * It uses SigmaComputation instance of a concrete sigma protocol to compute the actual messages. 
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class SigmaProver implements SigmaProtocolProver{
	
	/*
	 * This class manages the structure of all sigma provers:
	 * Prover message 1 (a):	SAMPLE a random values 
	 *  						COMPUTE first message
	 *  						SEND the computed message to the verifier
	 * Prover message 2 (z):	RECEIVE challenge from verifier
	 * 							COMPUTE second message
	 * 							SEND the computed message to the verifier
	 * 
	 * The actual computation of the messages is done by sigmaComputation class member.
	 */
	
	private Channel channel;
	private SigmaProverComputation proverComputation;	//Underlying sigma computation.
	private boolean doneFirstMsg;

	/**
	 * Constructor that sets the given channel and sigmaProverComputation.
	 * @param channel
	 * @param proverComputation
	 */
	public SigmaProver(Channel channel, SigmaProverComputation proverComputation){
		//Sets the parameters.
		this.channel = channel;
		this.proverComputation = proverComputation;
		
	}
	
	/**
	 * Runs the proof of this protocol. <p>
	 * This function executes the proof at once by calling the following functions one by one.<p>
	 * This function can be called when a user does not want to save time by doing operations in parallel.<p>
	 * @param input
	 */
	public void prove(SigmaProverInput input) throws CheatAttemptException, IOException, ClassNotFoundException{
		//Step one of the protocol.
		processFirstMsg(input);
		
		//Step two of the protocol.
		processSecondMsg();
	}
	
	/**
	 * Processes the first step of the sigma protocol.<p>
	 *  "SAMPLE a random values <p>
	 * 	 COMPUTE first message<p>
	 * 	 SEND the computed message to the verifier".<p>
	 * It computes the first message and sends it to the verifier.
	 */
	public void processFirstMsg(SigmaProverInput input) throws IOException{
	
		//Compute the first message by the underlying proverComputation.
		SigmaProtocolMsg a = proverComputation.computeFirstMsg(input);
		//Send the first message.
		sendMsgToVerifier(a);
		//save the state of this protocol.
		doneFirstMsg = true;
	}
	
	/**
	 * Processes the second step of the sigma protocol.<p>
	 * 	"RECEIVE challenge from verifier<p>
	 * 	 COMPUTE second message<p>
	 * 	 SEND the computed message to the verifier".<p>
	 * This is a blocking function!
	 */
	public void processSecondMsg() throws CheatAttemptException, IOException, ClassNotFoundException{
		
		if (!doneFirstMsg){
			throw new IllegalStateException("processFirstMsg should be called before processSecondMsg");
		}
		
		//Receive the challenge.
		byte[] e = receiveChallenge();
		
		//Compute the second message by the underlying proverComputation.
		SigmaProtocolMsg z = proverComputation.computeSecondMsg(e);
		
		//Send the second message.
		sendMsgToVerifier(z);
		
		//save the state of this sigma protocol.
		doneFirstMsg = false;
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
	
	/**
	 * Waits and receives the challenge from the verifier.
	 * @return byte[] the challenge
	 * @throws ClassNotFoundException
	 * @throws IOException if failed to receive the challenge.
	 */
	private byte[] receiveChallenge() throws ClassNotFoundException, IOException{
		Serializable challenge = null;
		try {
			challenge =  channel.receive();
		} catch (IOException e) {
			throw new IOException("failed to receive the challenge. The thrown exception is: " + e.getMessage());
		}
		if (!(challenge instanceof byte[])){
			throw new IllegalArgumentException("the given challenge should be a byte[]");
		}
		return (byte[]) challenge;
	}
}
