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
package edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.elGamalEncryptedValue;

import java.security.SecureRandom;

import edu.biu.scapi.exceptions.InvalidDlogGroupException;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.DlogBasedSigma;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.SigmaVerifierComputation;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.dh.SigmaDHCommonInput;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.dh.SigmaDHVerifierComputation;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaCommonInput;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaProtocolMsg;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;

/**
 * Concrete implementation of Sigma Protocol verifier computation. <p>
 * 
 * This protocol is used to prove that the value encrypted under ElGamal in the ciphertext (c1, c2) with public-key h is x.<p>
 * 
 * The pseudo code of this protocol can be found in Protocol 1.9 of pseudo codes document at {@link http://crypto.biu.ac.il/scapi/SDK_Pseudocode_SCAPI_V2.0.0.pdf}.<p>
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class SigmaElGamalEncryptedValueVerifierComputation implements SigmaVerifierComputation, DlogBasedSigma{

	/*	
	  There are two versions of SigmaElGamalEncryptedValue protocol, depending upon if the prover knows 
	  the secret key or it knows the randomness used to generate the ciphertext.
	  
	  This class uses an instance of SigmaDHProver with:
	  
	  		•	Common DlogGroup
	  	In case we use knowledge of the private key:
			•	Common input: (g,h,u,v) = (g,c1,h,c2/x) and
			•	P’s private input: a value w <- Zq such that h=g^w and c2/x =c1^w
		In case we use knowledge of the randomness used to encrypt:
			•	Common input: (g,h,u,v) = (g,h,c1,c2/x)
			•	P’s private input: a value r <- Zq such that c1=g^r and c2/x =h^r.
	*/	
	
	private SigmaDHVerifierComputation sigmaDH;	//underlying SigmaDHVerifier to use.
	private DlogGroup dlog;				//We save the dlog because we need it to calculate the input for the underlying Sigma verifier.
	
	/**
	 * Constructor that gets the underlying DlogGroup, soundness parameter and SecureRandom.
	 * @param dlog
	 * @param t Soundness parameter in BITS.
	 * @param random
	 * @throws InvalidDlogGroupException if the given dlog is invalid.
	 */
	public SigmaElGamalEncryptedValueVerifierComputation(DlogGroup dlog, int t, SecureRandom random) throws InvalidDlogGroupException {
		
		//Creates the underlying SigmaDHVerifier object with the given parameters.
		sigmaDH = new SigmaDHVerifierComputation(dlog, t, random);
		this.dlog = dlog;
	}
	
	/**
	 * Returns the soundness parameter for this Sigma protocol.
	 * @return t soundness parameter
	 */
	public int getSoundnessParam(){
		//Delegates to the underlying sigmaDH verifier.
		return sigmaDH.getSoundnessParam();
	}

	/**
	 * Sets the input for this Sigma protocol.
	 * @param input MUST be an instance of SigmaElGamalEncryptedValueCommonInput.
	 * @throws IllegalArgumentException if input is not the expected.
	 */
	private SigmaDHCommonInput convertInput(SigmaCommonInput in) {
		if (!(in instanceof SigmaElGamalEncryptedValueCommonInput)){
			throw new IllegalArgumentException("the given input must be an instance of SigmaElGamalEncryptedValueCommonInput");
		}
		
		SigmaElGamalEncryptedValueCommonInput params = (SigmaElGamalEncryptedValueCommonInput) in;
		boolean isRandomness = params.isRandomness();
		//Converts the given input to the necessary input to the underlying SigmaDHVerifier.
		GroupElement h = null;
		GroupElement u = null;;
		GroupElement v = null;
		
		//In case we use knowledge of the private key, the input should be:
		// (h, u, v) = (c1, h, c2/x) 
		if (!isRandomness){
			
			//h = c1;
			h = params.getCipher().getC1();
			//u = h;
			u = params.getPublicKey().getH();
			//v = c2/x = c2*x^(-1)
			GroupElement c2 = params.getCipher().getC2();
			GroupElement xInverse = dlog.getInverse(params.getX());
			v = dlog.multiplyGroupElements(c2, xInverse);
		}
		//In case we use knowledge of the randomness used to encrypt:
		// (h,u,v, w) = (h,c1,c2/x, r)
		if (isRandomness){
			//h = c1;
			h = params.getPublicKey().getH();
			//u = h;
			u = params.getCipher().getC1();
			//v = c2/x = c2*x^(-1)
			GroupElement c2 = params.getCipher().getC2();
			GroupElement xInverse = dlog.getInverse(params.getX());
			v = dlog.multiplyGroupElements(c2, xInverse);
		}
		
		
		//Create an input object to the underlying sigma DH verifier.
		return new SigmaDHCommonInput(h,u, v);
	}
	
	/**
	 * Samples the challenge e <- {0,1}^t.
	 */
	public void sampleChallenge(){
		//Delegates to the underlying Sigma DH verifier.
		sigmaDH.sampleChallenge();
	}
	
	/**
	 * Sets the given challenge.
	 * @param challenge
	 */
	public void setChallenge(byte[] challenge){
		//Delegates to the underlying Sigma DH verifier.
		sigmaDH.setChallenge(challenge);
	}
	
	/**
	 * Returns the sampled challenge.
	 * @return the challenge.
	 */
	public byte[] getChallenge(){
		//Delegates to the underlying Sigma DH verifier.
		return sigmaDH.getChallenge();
	}

	/**
	 * Verifies the proof.
	 * @param z second message from prover
	 * @return true if the proof has been verified; false, otherwise.
	 * @throws IllegalArgumentException if the first message of the prover is not an instance of SigmaDHMsg
	 * @throws IllegalArgumentException if the second message of the prover is not an instance of SigmaBIMsg
	 */
	public boolean verify(SigmaCommonInput in, SigmaProtocolMsg a, SigmaProtocolMsg z) {
		//converts the input to the underlying verifier.
		SigmaDHCommonInput input = convertInput(in);
		
		//Delegates to the underlying Sigma DH verifier.
		return sigmaDH.verify(input, a, z);
	}
}
