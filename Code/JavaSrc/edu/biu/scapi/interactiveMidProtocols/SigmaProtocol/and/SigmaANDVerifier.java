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
package edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.and;

import java.security.SecureRandom;
import java.util.ArrayList;

import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.SigmaVerifierComputation;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.utility.SigmaMultipleMsg;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.utility.SigmaProtocolInput;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.utility.SigmaProtocolMsg;

/**
 * Concrete implementation of Sigma Protocol verifier computation.
 * 
 * This protocol is used for a prover to convince a verifier that the AND of any number of statements are true, 
 * where each statement can be proven by an associated Sigma protocol.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class SigmaANDVerifier implements SigmaVerifierComputation{

	/*	
	  This class computes the following calculations:
		  	SAMPLE a random challenge  e <- {0, 1}^t 
			ACC IFF all verifier checks are ACC.         
	*/
	
	private ArrayList<SigmaVerifierComputation> verifiers;	// Underlying Sigma protocol's verifier to the AND calculation.
	private int len;										// number of underlying verifiers.
	private byte[] e;										//The challenge.
	private int t;											//Soundness parameter.
	private SecureRandom random;
	
	/**
	 * Constructor that gets the underlying verifiers.
	 * @param verifiers array of SigmaVerifierComputation, where each object represent a statement 
	 * 		  and the prover wants to prove to the verify that that the AND of all statements are true. 
	 * @param t soundness parameter. t MUST be equal to all t values of the underlying verifiers object.
	 * @param random source of randomness
	 * @throws IllegalArgumentException if the given t is not equal to all t values of the underlying verifiers object.
	 */
	public SigmaANDVerifier(ArrayList<SigmaVerifierComputation> verifiers, int t, SecureRandom random) {
		//If the given t is different from one of the underlying object's t values, throw exception.
		for (int i = 0; i < verifiers.size(); i++){
			if (t != verifiers.get(i).getSoundness()){
				throw new IllegalArgumentException("the given t does not equal to one of the t values in the underlying verifiers objects.");
			}
		}
		this.verifiers = verifiers;
		len = verifiers.size();
		this.t = t; 
		this.random = random;
	}
	
	/**
	 * Returns the soundness parameter for this Sigma protocol.
	 * @return t soundness parameter
	 */
	public int getSoundness(){
		return t;
	}


	/**
	 * Sets the inputs for each one of the underlying verifier.
	 * @param input MUST be an instance of SigmaANDInput.
	 * @throws IllegalArgumentException if input is not an instance of SigmaANDInput.
	 * @throws IllegalArgumentException if the number of given inputs is different from the number of underlying verifier.
	 */
	public void setInput(SigmaProtocolInput in) {
		if (!(in instanceof SigmaANDInput)){
			throw new IllegalArgumentException("the given input must be an instance of SigmaANDInput");
		}
		SigmaANDInput input = (SigmaANDInput) in;
		ArrayList<SigmaProtocolInput> verifiersInput = input.getInputs();
		int inputLen = verifiersInput.size();
		
		// If number of inputs is not equal to number of verifiers, throw exception.
		if (inputLen != len) {
			throw new IllegalArgumentException("number of inputs is different from number of underlying verifiers.");
		}
		
		//Sets the input to each underlying verifier.
		for (int i = 0; i < len; i++){
			verifiers.get(i).setInput(verifiersInput.get(i));
		}
	}
	
	/**
	 * Computes the following line from the protocol:
	 * 	"SAMPLE a random challenge e<-{0,1}^t".
	 */
	public void sampleChallenge(){
		//Create a new byte array of size t/8, to get the required byte size.
		e = new byte[t/8];
		//fills the byte array with random values.
		random.nextBytes(e);
		
		//Set all the other verifiers with the sampled challenge.
		for (int i = 0; i < len; i++){
			verifiers.get(i).setChallenge(e);
		}
	}
	
	/**
	 * Sets the given challenge.
	 * @param challenge
	 */
	public void setChallenge(byte[] challenge){
		//Set the challenge to all the underlying verifiers.
		for (int i = 0; i < len; i++){
			verifiers.get(i).setChallenge(challenge);
		}
	}
	
	/**
	 * Returns the sampled challenge.
	 * @return the challenge.
	 */
	public byte[] getChallenge(){
		return e;
	}

	/**
	 * Computes the following line from the protocol:
	 * 	"ACC IFF all verifier checks are ACC".
	 * @param a first message from prover
	 * @param z second message from prover
	 * @return true if the proof has been verified; false, otherwise.
	 * @throws IllegalArgumentException if the first or second message of the prover is not an instance of SigmaANDMsg
	 */
	public boolean verify(SigmaProtocolMsg a, SigmaProtocolMsg z) {
		
		boolean verified = true;
		
		//If one of the messages is illegal, throw exception.
		if (!(a instanceof SigmaMultipleMsg)){
			throw new IllegalArgumentException("first message must be an instance of SigmaANDMsg");
		}
		if (!(z instanceof SigmaMultipleMsg)){
			throw new IllegalArgumentException("second message must be an instance of SigmaANDMsg");
		}
		SigmaMultipleMsg first = (SigmaMultipleMsg) a; 
		SigmaMultipleMsg second = (SigmaMultipleMsg) z; 
		ArrayList<SigmaProtocolMsg> firstMessages = first.getMessages();
		ArrayList<SigmaProtocolMsg> secondMessages = second.getMessages();
		
		//Compute all verifier checks.
		for (int i = 0; i < len; i++){
			verified = verified && verifiers.get(i).verify(firstMessages.get(i), secondMessages.get(i));
		}
		
		//Return true if all verifiers returned true; false, otherwise.
		return verified;	
	}
	
}
