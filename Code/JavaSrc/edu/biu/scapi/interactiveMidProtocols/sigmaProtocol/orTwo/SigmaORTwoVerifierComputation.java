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
package edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.orTwo;

import java.security.SecureRandom;

import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.SigmaVerifierComputation;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaCommonInput;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaProtocolMsg;

/**
 * Concrete implementation of Sigma Protocol verifier computation.<p>
 * 
 * This protocol is used for a prover to convince a verifier that at least one of two statements is true, 
 * where each statement can be proven by an associated Sigma protocol.
 * 
 * For more information see Protocol 6.4.1, page 159 of Hazay-Lindell.<p>
 * The pseudo code of this protocol can be found in Protocol 1.15 of pseudo codes document at {@link http://crypto.biu.ac.il/scapi/SDK_Pseudocode_SCAPI_V2.0.0.pdf}.<p>
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class SigmaORTwoVerifierComputation implements SigmaVerifierComputation{
	
	/*		
	  Let (ai,ei,zi) denote the steps of a Sigma protocol SigmaI for proving that xi is in LRi (i=0,1)
	  This class computes the following calculations:
		  	SAMPLE a single random challenge  e <- {0, 1}^t
			ACC IFF all verifier checks are ACC.
	*/   
	
	private SigmaVerifierComputation[] verifiers;	// Underlying Sigma protocol verifiers to the OR calculation.
	private byte[] e;								//The challenge.
	private int t;									//Soundness parameter.
	private SecureRandom random;
	
	/**
	 * Constructor that gets the underlying verifiers.
	 * @param verifiers array of SigmaVerifierComputation that contains TWO underlying verifiers.
	 * @param t soundness parameter. t MUST be equal to both t values of the underlying verifiers objects.
	 * @throws IllegalArgumentException if the given t is not equal to both t values of the underlying verifiers.
	 * @throws IllegalArgumentException if the given verifiers array does not contains two objects.
	 */
	public SigmaORTwoVerifierComputation(SigmaVerifierComputation[] verifiers, int t, SecureRandom random) {
		if (verifiers.length != 2){
			throw new IllegalArgumentException("The given verifiers array must contains two objects.");
		}
		//If the given t is different from one of the underlying object's t values, throw exception.
		if ((t != verifiers[0].getSoundnessParam()) || (t != verifiers[1].getSoundnessParam())){
			throw new IllegalArgumentException("The given t does not equal to one of the t values in the underlying verifiers objects.");
		}
		
		this.verifiers = verifiers;
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
	 * Samples the challenge of the protocol.<p>
	 * 	"SAMPLE a random challenge e<-{0,1}^t".
	 */
	public void sampleChallenge(){
		//Create a new byte array of size t/8, to get the required byte size.
		e = new byte[t/8];
		//fills the byte array with random values.
		random.nextBytes(e);
	}
	
	/**
	 * Sets the given challenge.
	 * @param challenge
	 */
	public void setChallenge(byte[] challenge){
		//Set the challenge to e.
		e = challenge;
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
	 * @param input MUST be an instance of SigmaORTwoCommonInput.
	 * @param a first message from prover
	 * @param z second message from prover
	 * @return true if the proof has been verified; false, otherwise.
	 * @throws IllegalArgumentException if input is not an instance of SigmaORTwoCommonInput.
	 * @throws IllegalArgumentException if the first message of the prover is not an instance of SigmaORTwoFirstMsg
	 * @throws IllegalArgumentException if the second message of the prover is not an instance of SigmaORTwoSecondMsg
	 */
	public boolean verify(SigmaCommonInput in, SigmaProtocolMsg a, SigmaProtocolMsg z) {
		if (!(in instanceof SigmaORTwoCommonInput)){
			throw new IllegalArgumentException("The given input must be an instance of SigmaORTwoCommonInput");
		}
		SigmaORTwoCommonInput input = (SigmaORTwoCommonInput) in;
		
		boolean verified = true;
		
		//If one of the messages is illegal, throw exception.
		if (!(a instanceof SigmaORTwoFirstMsg)){
			throw new IllegalArgumentException("first message must be an instance of SigmaORTwoFirstMsg");
		}
		if (!(z instanceof SigmaORTwoSecondMsg)){
			throw new IllegalArgumentException("second message must be an instance of SigmaORTwoSecondMsg");
		}
		SigmaORTwoFirstMsg first = (SigmaORTwoFirstMsg) a; 
		SigmaORTwoSecondMsg second = (SigmaORTwoSecondMsg) z; 
		
		//Sets the challenges to the underlying verifiers.
		verifiers[0].setChallenge(second.getE0());
		verifiers[1].setChallenge(second.getE1());
		
		//Compute the first verify check
		verified = verified && verifiers[0].verify(input.getInputs()[0], first.getA0(), second.getZ0());
		
		//Compute the second verify check
		verified = verified && verifiers[1].verify(input.getInputs()[1], first.getA1(), second.getZ1());
		
		//Return true if all verifiers returned true; false, otherwise.
		return verified;	
	}
}
