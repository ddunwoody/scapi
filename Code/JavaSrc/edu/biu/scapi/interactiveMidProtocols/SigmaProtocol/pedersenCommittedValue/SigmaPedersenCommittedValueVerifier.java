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
package edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.pedersenCommittedValue;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;

import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.DlogBasedSigma;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.SigmaVerifierComputation;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.dlog.SigmaDlogInput;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.dlog.SigmaDlogVerifier;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.utility.SigmaProtocolInput;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.utility.SigmaProtocolMsg;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.dlog.cryptopp.CryptoPpDlogZpSafePrime;
import edu.biu.scapi.primitives.dlog.miracl.MiraclDlogECF2m;

/**
 * Concrete implementation of Sigma Protocol verifier computation. <p>
 * 
 * This protocol is used for a committer to prove that the value committed to in the commitment (h, c) is x.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class SigmaPedersenCommittedValueVerifier implements SigmaVerifierComputation, DlogBasedSigma{
	/*	
	  Since c = g^r*h^x, it suffices to prove knowledge of r s.t. g^r = c*h^(-x). This is just a DLOG Sigma protocol.
	  
	  This class uses an instance of SigmaDlogProver with:
	  	•	Common parameters (G,q,g) and t
		•	Common input: h’ = c*h^(-x) 
	*/
	
	private SigmaDlogVerifier sigmaDlog;	//underlying SigmaDlogVerifier to use.
	private DlogGroup dlog;					//We need the DlogGroup instance in order to calculate the input for the underlying SigmaDlogVerifier.
	
	/**
	 * Constructor that gets the underlying DlogGroup, soundness parameter and SecureRandom.
	 * @param dlog
	 * @param t Soundness parameter in BITS.
	 * @param random
	 */
	public SigmaPedersenCommittedValueVerifier(DlogGroup dlog, int t, SecureRandom random) {
		
		setParameters(dlog, t, random);
	}
	
	/**
	 * Default constructor that chooses default values for the parameters.
	 */
	public SigmaPedersenCommittedValueVerifier() {
		
		try {
			//Create Miracl Koblitz 233 Elliptic curve.
			dlog = new MiraclDlogECF2m("K-233");
		} catch (IOException e) {
			//If there is a problem with the elliptic curves file, create Zp DlogGroup.
			dlog = new CryptoPpDlogZpSafePrime();
		}
		
		setParameters(dlog, 80, new SecureRandom());
		
	}
	
	/**
	 * Sets the given parameters.
	 * @param dlog
	 * @param t Soundness parameter in BITS.
	 * @param random
	 */
	private void setParameters(DlogGroup dlog, int t, SecureRandom random) {
		
		//Creates the underlying SigmaDlogVerifier object with the given parameters.
		sigmaDlog = new SigmaDlogVerifier(dlog, t, random);
		this.dlog = dlog;
	}
	
	/**
	 * Returns the soundness parameter for this Sigma protocol.
	 * @return t soundness parameter
	 */
	public int getSoundness(){
		//Delegates to the underlying Sigma Dlog verifier.
		return sigmaDlog.getSoundness();
	}

	/**
	 * Sets the input for this Sigma protocol
	 * @param input MUST be an instance of SigmaPedersenCommittedValueInput.
	 * @throws IllegalArgumentException if input is not an instance of SigmaPedersenCommittedValueInput.
	 */
	public void setInput(SigmaProtocolInput in) {
		
		if (!(in instanceof SigmaPedersenCommittedValueInput)){
			throw new IllegalArgumentException("the given input must be an instance of SigmaPedersenCommittedValueInput");
		}
		SigmaPedersenCommittedValueInput input = (SigmaPedersenCommittedValueInput) in;
		
		//Convert the input to the underlying Dlog prover. h’ = c*h^(-x).
		BigInteger minusX = dlog.getOrder().subtract(input.getX());
		GroupElement hToX = dlog.exponentiate(input.getH(), minusX);
		GroupElement c = dlog.reconstructElement(true, input.getCommitment().getC());
		GroupElement hTag = dlog.multiplyGroupElements(c, hToX);
		
		SigmaDlogInput underlyingInput = new SigmaDlogInput(hTag);
		sigmaDlog.setInput(underlyingInput);
				
	}
	
	/**
	 * Samples the challenge e <- {0,1}^t
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
	public boolean verify(SigmaProtocolMsg a, SigmaProtocolMsg z) {
		
		return sigmaDlog.verify(a, z);
	}

}
