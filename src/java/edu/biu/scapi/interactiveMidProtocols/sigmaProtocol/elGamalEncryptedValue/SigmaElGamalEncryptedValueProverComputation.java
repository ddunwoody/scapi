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

import java.math.BigInteger;
import java.security.SecureRandom;

import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.DlogBasedSigma;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.SigmaProverComputation;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.SigmaSimulator;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.dh.SigmaDHProverComputation;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.dh.SigmaDHProverInput;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaProverInput;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaProtocolMsg;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;

/**
 * Concrete implementation of Sigma Protocol prover computation. <p>
 * 
 * This protocol is used to prove that the value encrypted under ElGamal in the ciphertext (c1, c2) with public-key h is x.<p>
 * 
 * The pseudo code of this protocol can be found in Protocol 1.9 of pseudo codes document at {@link http://crypto.biu.ac.il/scapi/SDK_Pseudocode_SCAPI_V2.0.0.pdf}.<p>
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class SigmaElGamalEncryptedValueProverComputation implements SigmaProverComputation, DlogBasedSigma{

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
	
	private SigmaDHProverComputation sigmaDH;	//underlying SigmaDHProver to use.
	private DlogGroup dlog;			//We save the dlog because we need it to calculate the input for the underlying Sigma prover.
	
	/**
	 * Constructor that gets the underlying DlogGroup, soundness parameter and SecureRandom.
	 * @param dlog
	 * @param t Soundness parameter in BITS.
	 * @param random
	 */
	public SigmaElGamalEncryptedValueProverComputation(DlogGroup dlog, int t, SecureRandom random) {
		
		//Creates the underlying SigmaDHProver object with the given parameters.
		sigmaDH = new SigmaDHProverComputation(dlog, t, random);
		this.dlog = dlog;
	}
	
	/**
	 * Returns the soundness parameter for this Sigma protocol.
	 * @return t soundness parameter
	 */
	public int getSoundnessParam(){
		//Delegates the computation to the underlying Sigma DH prover.
		return sigmaDH.getSoundnessParam();
	}

	/**
	 * Converts the input for the underlying Sigma protocol.
	 * There are two versions of this protocol, depending upon if the prover knows the secret key or it knows the randomness used to generate the ciphertext.
	 * The only separation in these two version is the type of input. 
	 * In case we use knowledge of private key, the input should be an instance of SigmaElGamalEncryptedValuePrivKeyProverInput.
	 * In case we use knowledge of randomness, the input should be an instance of SigmaElGamalEncryptedValueRandomnessProverInput.
	 * @param input MUST be an instance of SigmaElGamalEncryptedValuePrivKeyProverInput OR SigmaElGamalEncryptedValueRandomnessProverInput.
	 * @throws IllegalArgumentException if input is not the expected.
	 */
	private SigmaDHProverInput convertInput(SigmaProverInput in) {
		
		//Converts the given input to the necessary input to the underlying SigmaDHProver.
		GroupElement h;
		GroupElement u;
		GroupElement v;
		BigInteger w;
		
		//In case we use knowledge of the private key, the input should be:
		// (h, u, v, w) = (c1, h, c2/x, w) 
		if (in instanceof SigmaElGamalEncryptedValuePrivKeyProverInput){
			SigmaElGamalEncryptedValuePrivKeyProverInput input = (SigmaElGamalEncryptedValuePrivKeyProverInput) in;
			SigmaElGamalEncryptedValueCommonInput params = input.getCommonParams();
			//h = c1;
			h = params.getCipher().getC1();
			//u = h;
			u = params.getPublicKey().getH();
			//v = c2/x = c2*x^(-1)
			GroupElement c2 = params.getCipher().getC2();
			GroupElement xInverse = dlog.getInverse(params.getX());
			v = dlog.multiplyGroupElements(c2, xInverse);
			//get the private key.
			w = input.getPrivateKey().getX();
		}
		//In case we use knowledge of the randomness used to encrypt:
		// (h,u,v, w) = (h,c1,c2/x, r)
		else if (in instanceof SigmaElGamalEncryptedValueRandomnessProverInput){
			SigmaElGamalEncryptedValueRandomnessProverInput input = (SigmaElGamalEncryptedValueRandomnessProverInput) in;
			SigmaElGamalEncryptedValueCommonInput params = input.getCommonParams();
			//h = h;
			h = params.getPublicKey().getH();
			//u = c1;
			u = params.getCipher().getC1();
			//v = c2/x = c2*x^(-1)
			GroupElement c2 = params.getCipher().getC2();
			GroupElement xInverse = dlog.getInverse(params.getX());
			v = dlog.multiplyGroupElements(c2, xInverse);
			//get the randomness.
			w = input.getR();
		}
		else {
			throw new IllegalArgumentException("the given input must be an instance of SigmaElGamalEncryptedValuePrivKeyProverInput " +
												"or SigmaElGamalEncryptedValueRandomnessProverInput");
		}
		
		
		//Create an input object to the underlying sigma DH prover.
		return new SigmaDHProverInput(h,u, v, w);
		
	}

	/**
	 * Computes the first message of the protocol.
	 * @return the computed message
	 */
	public SigmaProtocolMsg computeFirstMsg(SigmaProverInput in) {
		//Converts the input to the underlying prover.
		SigmaDHProverInput input = convertInput(in);
		
		//Delegates the computation to the underlying Sigma DH prover.
		return sigmaDH.computeFirstMsg(input);
	}

	/**
	 * Computes the second message of the protocol.
	 * @param challenge
	 * @return the computed message.
	 * @throws CheatAttemptException if the received challenge's length is not equal to the soundness parameter.
	 */
	public SigmaProtocolMsg computeSecondMsg(byte[] challenge) throws CheatAttemptException {
		//Delegates the computation to the underlying Sigma DH prover.
		return sigmaDH.computeSecondMsg(challenge);
		
	}
	
	/**
	 * Returns the simulator that matches this sigma protocol prover.
	 * @return SigmaDlogSimulator
	 */
	public SigmaSimulator getSimulator(){
		return new SigmaElGamalEncryptedValueSimulator(sigmaDH.getSimulator());
	}

}
