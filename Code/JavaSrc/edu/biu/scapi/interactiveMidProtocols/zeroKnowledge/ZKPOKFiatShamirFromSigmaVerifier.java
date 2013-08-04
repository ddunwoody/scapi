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
import edu.biu.scapi.exceptions.CommitValueException;
import edu.biu.scapi.exceptions.SecurityLevelException;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.SigmaVerifierComputation;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.utility.SigmaProtocolInput;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.utility.SigmaProtocolMsg;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CTCommitter;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CommitValue;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.OnBigIntegerCommitmentScheme;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.OnByteArrayCommitmentScheme;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.PedersenCTCommitter;
import edu.biu.scapi.primitives.hash.CryptographicHash;
import edu.biu.scapi.primitives.hash.cryptopp.CryptoPpSHA1;
import edu.biu.scapi.securityLevel.PerfectlyHidingCT;

/**
 * Concrete implementation of Zero Knowledge verifier.
 * 
 * This is a transformation that takes any Sigma protocol and a random oracle 
 * (instantiated with any hash function) H and yields a zero-knowledge proof of knowledge.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class ZKPOKFiatShamirFromSigmaVerifier implements ZeroKnowledgeVerifier{

	private Channel channel;
	private SigmaVerifierComputation sVerifier; //Underlying verifier that computes the proof of the sigma protocol.
	private CryptographicHash hash;			//Underlying hash to use as random oracle.
	private ZKPOKFiatShamirInput input;		//possible context information cont, given in the input.
	
	/**
	 * Constructor that accepts the underlying channel, sigma protocol's verifier and hash to use.
	 * @param channel
	 * @param sVerifier
	 * @param hash
	 */
	public ZKPOKFiatShamirFromSigmaVerifier(Channel channel, SigmaVerifierComputation sVerifier, CryptographicHash hash) {
		
		this.sVerifier = sVerifier;
		this.hash = hash;
		this.channel = channel;
	}
	
	/**
	 * Constructor that accepts the underlying channel, sigma protocol's verifier and sets default hash.
	 * @param channel
	 * @param sVerifier
	 */
	public ZKPOKFiatShamirFromSigmaVerifier(Channel channel, SigmaVerifierComputation sVerifier){
	
		this.channel = channel;
		this.sVerifier = sVerifier;
		this.hash = new CryptoPpSHA1();
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
		
		sVerifier.setInput(this.input.getSigmaInput());
	}
	
	/**
	 * Runs the verifier side of the Zero Knowledge proof.
	 * Let (a,e,z) denote the prover1, verifier challenge and prover2 messages of the sigma protocol.
	 * This function computes the following calculations:
	 *
	 *		IF
	 *			•	e=H(x,a,cont), AND
	 *			•	Transcript (a, e, z) is accepting in sigma on input x
	 *     		OUTPUT ACC
	 *     ELSE
	 *          OUTPUT REJ
	 * @throws IOException if failed to send the message.
	 * @throws ClassNotFoundException 
	 */
	public boolean verify() throws ClassNotFoundException, IOException{
		
		//Wait for a message a from P
		SigmaProtocolMsg a = receiveMsgFromProver();
		
		//Compute e=H(x,a,cont)
		byte[] computedE = computeChallenge(a);
		
		//Wait for a message e from P, 
		byte[] receivedE = receiveChallengeFromProver();
		
		//check that e=H(x,a,cont):
		boolean valid = true;
		//In case that lengths of computed e and received e are not the same, set valid to false.
		if (computedE.length != receivedE.length){
			valid = false;
		}
		
		//In case that  computed e and received e are not the same, set valid to false.
		for (int i = 0; i<computedE.length; i++){
			if (computedE[i] != receivedE[i]){
				valid = false;
			}
		}
			
		//Wait for a message z from P
		SigmaProtocolMsg z = receiveMsgFromProver();
		
		//If transcript (a, e, z) is accepting in sigma on input x, output ACC
		//Else outupt REJ
		valid = valid && proccessVerify(a, computedE, z);
		
		return valid;
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
	 * Waits for a message a from the prover.
	 * @return the received message
	 * @throws ClassNotFoundException
	 * @throws IOException if failed to send the message.
	 */
	private byte[] receiveChallengeFromProver() throws ClassNotFoundException, IOException {
		Serializable msg = null;
		try {
			//receive the mesage.
			msg = channel.receive();
		} catch (IOException e) {
			throw new IOException("failed to receive the a message. The thrown message is: " + e.getMessage());
		}
		//If the given message is not an instance of SigmaProtocolMsg, throw exception.
		if (!(msg instanceof byte[])){
			throw new IllegalArgumentException("the given message should be a byte[]");
		}
		//Return the given message.
		return (byte[]) msg;
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
	 * Verifies the proof.
	 * @param a first message from prover.
	 * @throws IOException if failed to send the message.
	 * @throws ClassNotFoundException 
	 */
	private boolean proccessVerify(SigmaProtocolMsg a, byte[] challenge, SigmaProtocolMsg z) {
		//If transcript (a, e, z) is accepting in sigma on input x, output ACC
		//Else outupt REJ
		
		sVerifier.setChallenge(challenge);
		
		return sVerifier.verify(a, z);
	}
}

