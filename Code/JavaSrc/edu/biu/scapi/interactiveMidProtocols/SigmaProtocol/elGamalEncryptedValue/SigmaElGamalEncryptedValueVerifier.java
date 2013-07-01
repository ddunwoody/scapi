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
package edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.elGamalEncryptedValue;

import java.io.IOException;
import java.security.SecureRandom;

import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.DlogBasedSigma;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.SigmaVerifierComputation;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.dh.SigmaDHInput;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.dh.SigmaDHVerifier;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.utility.SigmaProtocolInput;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.utility.SigmaProtocolMsg;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.dlog.cryptopp.CryptoPpDlogZpSafePrime;
import edu.biu.scapi.primitives.dlog.miracl.MiraclDlogECF2m;

/**
 * Concrete implementation of Sigma Protocol verifier computation. <p>
 * 
 * This protocol is used to prove that the value encrypted under ElGamal in the ciphertext (c1, c2) with public-key h is x.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class SigmaElGamalEncryptedValueVerifier implements SigmaVerifierComputation, DlogBasedSigma{

	/*	
	  This class uses an instance of SigmaDHProver with:
	  
	  		•	Common DlogGroup
	  	In case we use knowledge of the private key:
			•	Common input: (g,h,u,v) = (g,c1,h,c2/x) and
			•	P’s private input: a value w <- Zq such that h=g^w and c2/x =c1^w
		In case we use knowledge of the randomness used to encrypt:
			•	Common input: (g,h,u,v) = (g,h,c1,c2/x)
			•	P’s private input: a value r <- Zq such that c1=g^r and c2/x =h^r.
	*/	
	
	private SigmaDHVerifier sigmaDH;	//underlying SigmaDlogVerifier to use.
	private DlogGroup dlog;				//We save the dlog because we need it to calculate the input for the underlying Sigma verifier.
	
	/**
	 * Constructor that gets the underlying DlogGroup, soundness parameter and SecureRandom.
	 * @param dlog
	 * @param t Soundness parameter in BITS.
	 * @param random
	 */
	public SigmaElGamalEncryptedValueVerifier(DlogGroup dlog, int t, SecureRandom random) {
		
		//Creates the underlying SigmaDlogVerifier object with the given parameters.
		sigmaDH = new SigmaDHVerifier(dlog, t, random);
		this.dlog = dlog;
	}
	
	/**
	 * Default constructor that chooses default values for the parameters.
	 */
	public SigmaElGamalEncryptedValueVerifier() {
		try {
			//Create Miracl Koblitz 233 Elliptic curve.
			dlog = new MiraclDlogECF2m("K-233");
		} catch (IOException e) {
			//If there is a problem with the elliptic curves file, create Zp DlogGroup.
			dlog = new CryptoPpDlogZpSafePrime();
		}
		
		//Creates the underlying SigmaDHVerifier object with default parameters.
		sigmaDH = new SigmaDHVerifier(dlog, 80, new SecureRandom());
	}
	
	/**
	 * Returns the soundness parameter for this Sigma protocol.
	 * @return t soundness parameter
	 */
	public int getSoundness(){
		//Delegates to the underlying sigmaDH verifier.
		return sigmaDH.getSoundness();
	}

	/**
	 * Sets the input for this Sigma protocol.
	 * There are two versions of this protocol, depending upon if the prover knows the secret key or it knows the randomness used to generate the ciphertext.
	 * The only separation in these two version is the type of input. 
	 * In case we use knowledge of private key, the input should be an instance of SigmaElGamalEncryptedValuePrivKeyInput.
	 * In case we use knowledge of randomness, the input should be an instance of SigmaElGamalEncryptedValueRandomnessInput.
	 * @param input MUST be an instance of SigmaElGamalEncryptedValuePrivKeyInput OR SigmaElGamalEncryptedValueRandomnessInput.
	 * @throws IllegalArgumentException if input is not the expected.
	 */
	public void setInput(SigmaProtocolInput in) {
		//Converts the given input to the necessary input to the underlying SigmaDHVerifier.
		GroupElement h;
		GroupElement u;
		GroupElement v;
		
		//In case we use knowledge of the private key, the input should be:
		// (h, u, v, w) = (c1, h, c2/x, w) 
		if (in instanceof SigmaElGamalEncryptedValuePrivKeyInput){
			SigmaElGamalEncryptedValuePrivKeyInput input = (SigmaElGamalEncryptedValuePrivKeyInput) in;
			//h = c1;
			h = input.getCipher().getC1();
			//u = h;
			u = input.getPublicKey().getH();
			//v = c2/x = c2*x^(-1)
			GroupElement c2 = input.getCipher().getC2();
			GroupElement xInverse = dlog.getInverse(input.getX());
			v = dlog.multiplyGroupElements(c2, xInverse);
		}
		//In case we use knowledge of the randomness used to encrypt:
		// (h,u,v, w) = (h,c1,c2/x, r)
		else if (in instanceof SigmaElGamalEncryptedValueRandomnessInput){
			SigmaElGamalEncryptedValueRandomnessInput input = (SigmaElGamalEncryptedValueRandomnessInput) in;
			//h = c1;
			h = input.getPublicKey().getH();
			//u = h;
			u = input.getCipher().getC1();
			//v = c2/x = c2*x^(-1)
			GroupElement c2 = input.getCipher().getC2();
			GroupElement xInverse = dlog.getInverse(input.getX());
			v = dlog.multiplyGroupElements(c2, xInverse);
		}
		else {
			throw new IllegalArgumentException("the given input must be an instance of SigmaElGamalEncryptedValuePrivKeyInput " +
												"or SigmaElGamalEncryptedValueRandomnessInput");
		}
		
		
		//Create an input object to the underlying sigma DH verifier.
		SigmaDHInput underlyingInput = new SigmaDHInput(h,u, v);
		sigmaDH.setInput(underlyingInput);
		
	}
	
	/**
	 * Samples the challenge e <- {0,1}^t
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
	 * @throws IllegalArgumentException if the first message of the prover is not an instance of SigmaGroupElementMsg
	 * @throws IllegalArgumentException if the second message of the prover is not an instance of SigmaBIMsg
	 */
	public boolean verify(SigmaProtocolMsg a, SigmaProtocolMsg z) {
		//Delegates to the underlying Sigma DH verifier.
		return sigmaDH.verify(a, z);
	}
}
