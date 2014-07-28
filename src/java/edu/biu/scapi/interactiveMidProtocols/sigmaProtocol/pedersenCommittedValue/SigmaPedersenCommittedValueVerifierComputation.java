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
package edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.pedersenCommittedValue;

import java.math.BigInteger;
import java.security.SecureRandom;

import edu.biu.scapi.exceptions.InvalidDlogGroupException;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.DlogBasedSigma;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.SigmaVerifierComputation;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.dlog.SigmaDlogCommonInput;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.dlog.SigmaDlogVerifierComputation;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaCommonInput;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaProtocolMsg;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;

/**
 * Concrete implementation of Sigma Protocol verifier computation. <p>
 * 
 * This protocol is used for a committer to prove that the value committed to in the commitment (h, c) is x.<p>
 * 
 * The pseudo code of this protocol can be found in Protocol 1.5 of pseudo codes document at {@link http://crypto.biu.ac.il/scapi/SDK_Pseudocode_SCAPI_V2.0.0.pdf}.<p>
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class SigmaPedersenCommittedValueVerifierComputation implements SigmaVerifierComputation, DlogBasedSigma{
	/*	
	  Since c = g^r*h^x, it suffices to prove knowledge of r s.t. g^r = c*h^(-x). This is just a DLOG Sigma protocol.
	  
	  This class uses an instance of SigmaDlogProver with:
	  	•	Common parameters (G,q,g) and t
		•	Common input: h’ = c*h^(-x) 
	*/
	
	private SigmaDlogVerifierComputation sigmaDlog;	//underlying SigmaDlogVerifier to use.
	private DlogGroup dlog;					//We need the DlogGroup instance in order to calculate the input for the underlying SigmaDlogVerifier.
	
	/**
	 * Constructor that gets the underlying DlogGroup, soundness parameter and SecureRandom.
	 * @param dlog
	 * @param t Soundness parameter in BITS.
	 * @param random
	 * @throws InvalidDlogGroupException if the given dlog is invalid.
	 */
	public SigmaPedersenCommittedValueVerifierComputation(DlogGroup dlog, int t, SecureRandom random) throws InvalidDlogGroupException {
		
		//Creates the underlying SigmaDlogVerifier object with the given parameters.
		sigmaDlog = new SigmaDlogVerifierComputation(dlog, t, random);
		this.dlog = dlog;
	}
	
	/**
	 * Returns the soundness parameter for this Sigma protocol.
	 * @return t soundness parameter
	 */
	public int getSoundnessParam(){
		//Delegates to the underlying Sigma Dlog verifier.
		return sigmaDlog.getSoundnessParam();
	}

	/**
	 * Sets the input for this Sigma protocol.
	 * @param input MUST be an instance of SigmaPedersenCommittedValueCommonInput.
	 * @throws IllegalArgumentException if input is not an instance of SigmaPedersenCommittedValueCommonInput.
	 */
	private SigmaDlogCommonInput convertInput(SigmaCommonInput in) {
		
		if (!(in instanceof SigmaPedersenCommittedValueCommonInput)){
			throw new IllegalArgumentException("the given input must be an instance of SigmaPedersenCommittedValueCommonInput");
		}
		SigmaPedersenCommittedValueCommonInput input = (SigmaPedersenCommittedValueCommonInput) in;
		
		//Convert the input to the underlying Dlog prover. h’ = c*h^(-x).
		BigInteger minusX = dlog.getOrder().subtract(input.getX());
		GroupElement hToX = dlog.exponentiate(input.getH(), minusX);
		GroupElement c = input.getCommitment();
		GroupElement hTag = dlog.multiplyGroupElements(c, hToX);
		
		return new SigmaDlogCommonInput(hTag);
				
	}
	
	/**
	 * Samples the challenge e <- {0,1}^t.
	 */
	public void sampleChallenge(){
		//Delegates to the underlying Sigma Dlog verifier.
		sigmaDlog.sampleChallenge();
	}
	
	/**
	 * Sets the given challenge.
	 * @param challenge
	 */
	public void setChallenge(byte[] challenge){
		//Delegates to the underlying Sigma Dlog verifier.
		sigmaDlog.setChallenge(challenge);
	}
	
	/**
	 * Returns the sampled challenge.
	 * @return the challenge.
	 */
	public byte[] getChallenge(){
		//Delegates to the underlying Sigma Dlog verifier.
		return sigmaDlog.getChallenge();
	}

	/**
	 * Verifies the proof.
	 * @param z second message from prover
	 * @return true if the proof has been verified; false, otherwise.
	 * @throws IllegalArgumentException if the first message of the prover is not an instance of SigmaGroupElementMsg
	 * @throws IllegalArgumentException if the second message of the prover is not an instance of SigmaBIMsg
	 */
	public boolean verify(SigmaCommonInput in, SigmaProtocolMsg a, SigmaProtocolMsg z) {
		//Converts the input to the underlying verifier.
		SigmaDlogCommonInput input = convertInput(in);
		
		return sigmaDlog.verify(input, a, z);
	}

}
