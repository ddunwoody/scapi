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
import edu.biu.scapi.exceptions.SecurityLevelException;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.SigmaProverComputation;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.utility.SigmaProtocolMsg;
import edu.biu.scapi.primitives.hash.CryptographicHash;
import edu.biu.scapi.primitives.hash.cryptopp.CryptoPpSHA1;

/**
 * Concrete implementation of Zero Knowledge prover.
 * 
 * This is a transformation that takes any Sigma protocol and a random oracle 
 * (instantiated with any hash function) H and yields a zero-knowledge proof of knowledge.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class ZKPOKFiatShamirFromSigmaProver implements ZeroKnowledgeProver{

	private Channel channel;
	private SigmaProverComputation sProver; //Underlying prover that computes the proof of the sigma protocol.
	private CryptographicHash hash;			//Underlying hash to use as random oracle.
	private ZKPOKFiatShamirInput input;		//possible context information cont, given in the input.
	
	/**
	 * Constructor that accepts the underlying channel, sigma protocol's prover and CryptographicHash to use.
	 * @param channel
	 * @param sProver
	 * @param hash
	 */
	public ZKPOKFiatShamirFromSigmaProver(Channel channel, SigmaProverComputation sProver, CryptographicHash hash) {
		
		this.sProver = sProver;
		this.hash = hash;
		this.channel = channel;
	}
	
	/**
	 * Constructor that accepts the underlying channel, sigma protocol's prover and sets default hash function.
	 * @param channel
	 * @param sProver
	 */
	public ZKPOKFiatShamirFromSigmaProver(Channel channel, SigmaProverComputation sProver){
		
		this.sProver = sProver;
		this.hash = new CryptoPpSHA1();
		this.channel = channel;
	}
	
	/**
	 * Sets the input for this Zero Knowledge protocol.
	 * @param input must be an instance of ZKPOKFiatShamirInput that holds 
	 * 				input for the underlying sigma protocol and possible context information cont.
	 * @throws IllegalArgumentException if the given input is not an instance of ZKPOKFiatShamirInput.
	 */
	public void setInput(ZeroKnowledgeInput input){
		//The given input must be an instance of ZKPOKFiatShamirInput that holds input for the underlying sigma protocol and possible context information cont.
		if (!(input instanceof ZKPOKFiatShamirInput)){
			throw new IllegalArgumentException("the given input must be an instance of ZKPOKFiatShamirInput");
		}
		this.input = (ZKPOKFiatShamirInput) input;
		
		sProver.setInput(this.input.getSigmaInput());
	}
	
	/**
	 * Runs the prover side of the Zero Knowledge proof.
	 * Let (a,e,z) denote the prover1, verifier challenge and prover2 messages of the sigma protocol.
	 * This function computes the following calculations:
	 *
	 *		 COMPUTE the first message a in sigma, using (x,w) as input
	 *		 COMPUTE e=H(x,a,cont)
	 *		 COMPUTE the response z to (a,e) according to sigma
	 *		 SEND (a,e,z) to V
	 *		 OUTPUT nothing

	 * @throws IOException if failed to send the message.
	 * @throws ClassNotFoundException 
	 */
	public void prove() throws IOException, CheatAttemptException, ClassNotFoundException {
		
		//Compute the first message a in sigma, using (x,w) as input and 
		sProver.sampleRandomValues();
		SigmaProtocolMsg a = sProver.computeFirstMsg();
		
		//Compute e=H(x,a,cont)
		byte[] e = computeChallenge(a);
		
		//Compute the response z to (a,e) according to sigma
		SigmaProtocolMsg z = sProver.computeSecondMsg(e);
		
		//Send (a,e,z) to V and output nothing.
		sendMsgToVerifier(a);
		sendMsgToVerifier(e);
		sendMsgToVerifier(z);
		
	}
	
	/**
	 * Run the following line from the protocol:
	 * "COMPUTE e=H(x,a,cont)".
	 * @param a first message of the sigma protocol.
	 * @return the computed challenge
	 */
	private byte[] computeChallenge(SigmaProtocolMsg a) {
		byte[] inputArray = input.getSigmaInput().toByteArray();
		byte[] messageArray = a.toByteArray();
		byte[] cont = input.getCont();
		
		byte[] input = null;
		
		if (cont != null){
			input = new byte[inputArray.length + messageArray.length + cont.length];
			System.arraycopy(cont, 0, input, inputArray.length + messageArray.length, cont.length);
		} else{
			input = new byte[inputArray.length + messageArray.length];
		}
		System.arraycopy(inputArray, 0, input, 0, inputArray.length);
		System.arraycopy(messageArray, 0, input, inputArray.length, messageArray.length);
		
		hash.update(input, 0, input.length);
		//challenge should be of size t - how can we do this?
		byte[] challenge = new byte[hash.getHashedMsgSize()];
		hash.hashFinal(challenge, 0);
		return challenge;
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
