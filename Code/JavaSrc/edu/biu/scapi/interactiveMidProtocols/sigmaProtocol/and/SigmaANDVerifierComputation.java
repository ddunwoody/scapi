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
package edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.and;

import java.security.SecureRandom;
import java.util.ArrayList;

import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.SigmaVerifierComputation;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaCommonInput;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaMultipleMsg;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaProtocolMsg;

/**
 * Concrete implementation of Sigma Protocol verifier computation.<p>
 * 
 * This protocol is used for a prover to convince a verifier that the AND of any number of statements are true, 
 * where each statement can be proven by an associated Sigma protocol.<p>
 * 
 * The pseudo code of this protocol can be found in Protocol 1.14 of pseudo codes document at {@link http://crypto.biu.ac.il/scapi/SDK_Pseudocode_SCAPI_V2.0.0.pdf}.<p>
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class SigmaANDVerifierComputation implements SigmaVerifierComputation{

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
	public SigmaANDVerifierComputation(ArrayList<SigmaVerifierComputation> verifiers, int t, SecureRandom random) {
		//If the given t is different from one of the underlying object's t values, throw exception.
		for (int i = 0; i < verifiers.size(); i++){
			if (t != verifiers.get(i).getSoundnessParam()){
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
	public int getSoundnessParam(){
		return t;
	}


	/**
	 * Sets the inputs for each one of the underlying verifier.
	 * @param input MUST be an instance of SigmaANDCommonInput.
	 * @throws IllegalArgumentException if input is not an instance of SigmaANDCommonInput.
	 * @throws IllegalArgumentException if the number of given inputs is different from the number of underlying verifier.
	 */
	private void checkInput(SigmaCommonInput in) {
		if (!(in instanceof SigmaANDCommonInput)){
			throw new IllegalArgumentException("the given input must be an instance of SigmaANDCommonInput");
		}
		SigmaANDCommonInput input = (SigmaANDCommonInput) in;
		int inputLen = input.getInputs().size();
		
		// If number of inputs is not equal to number of verifiers, throw exception.
		if (inputLen != len) {
			throw new IllegalArgumentException("number of inputs is different from number of underlying verifiers.");
		}
	
	}
	
	/**
	 * Samples the challenge of the protocol.<p>
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
	 * Computes the verification of the protocol.<p>
	 * 	"ACC IFF all verifier checks are ACC".
	 * @param input MUST be an instance of SigmaANDCommonInput.
	 * @param a first message from prover
	 * @param z second message from prover
	 * @return true if the proof has been verified; false, otherwise.
	 * @throws IllegalArgumentException if input is not an instance of SigmaANDCommonInput.
	 * @throws IllegalArgumentException if the number of given inputs is different from the number of underlying verifier.
	 * @throws IllegalArgumentException if the first or second message of the prover is not an instance of SigmaMultipleMsg
	 */
	public boolean verify(SigmaCommonInput in, SigmaProtocolMsg a, SigmaProtocolMsg z) {
		//Checks that the input is as expected.
		checkInput(in);
		ArrayList<SigmaCommonInput> verifiersInput = ((SigmaANDCommonInput) in).getInputs();
		
		boolean verified = true;
		
		//If one of the messages is illegal, throw exception.
		if (!(a instanceof SigmaMultipleMsg)){
			throw new IllegalArgumentException("first message must be an instance of SigmaMultipleMsg");
		}
		if (!(z instanceof SigmaMultipleMsg)){
			throw new IllegalArgumentException("second message must be an instance of SigmaMultipleMsg");
		}
		SigmaMultipleMsg first = (SigmaMultipleMsg) a; 
		SigmaMultipleMsg second = (SigmaMultipleMsg) z; 
		ArrayList<SigmaProtocolMsg> firstMessages = first.getMessages();
		ArrayList<SigmaProtocolMsg> secondMessages = second.getMessages();
		
		//Compute all verifier checks.
		for (int i = 0; i < len; i++){
			verified = verified && verifiers.get(i).verify(verifiersInput.get(i), firstMessages.get(i), secondMessages.get(i));
		}
		
		//Return true if all verifiers returned true; false, otherwise.
		return verified;	
	}
	
}
