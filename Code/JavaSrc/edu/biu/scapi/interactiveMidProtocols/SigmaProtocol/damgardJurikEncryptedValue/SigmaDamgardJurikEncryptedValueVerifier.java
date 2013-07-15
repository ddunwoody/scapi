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
package edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.damgardJurikEncryptedValue;

import java.math.BigInteger;
import java.security.SecureRandom;

import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.DJBasedSigma;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.SigmaVerifierComputation;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.damgardJurikEncryptedZero.SigmaDJEncryptedZeroInput;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.damgardJurikEncryptedZero.SigmaDamgardJurikEncryptedZeroVerifier;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.utility.SigmaProtocolInput;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.utility.SigmaProtocolMsg;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.DamgardJurikPublicKey;
import edu.biu.scapi.midLayer.ciphertext.BigIntegerCiphertext;
import edu.biu.scapi.midLayer.plaintext.BigIntegerPlainText;

/**
 * Concrete implementation of Sigma Protocol verifier computation. <p>
 * 
 * This protocol is used for a party who encrypted a value x to prove that it indeed encrypted x.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class SigmaDamgardJurikEncryptedValueVerifier implements SigmaVerifierComputation, DJBasedSigma {

	/*	
	  This class uses an instance of SigmaDamgardJurikEncryptedZeroVerifier with:
	  	•	Common input: (n,c’) where c’=c*(1+n)^(-x) mod N'
	
	*/	
	
	private SigmaDamgardJurikEncryptedZeroVerifier sigmaDamgardJurik;	//underlying SigmaDamgardJurikVerifier to use.
	private int lengthParameter;										// length parameter in BITS.
	
	
	/**
	 * Constructor that gets the underlying DlogGroup, soundness parameter and SecureRandom.
	 * @param dlog
	 * @param t Soundness parameter in BITS.
	 * @param random
	 */
	public SigmaDamgardJurikEncryptedValueVerifier(int t, int lengthParameter, SecureRandom random) {
		
		//Creates the underlying sigmaDamgardJurik object with the given parameters.
		sigmaDamgardJurik = new SigmaDamgardJurikEncryptedZeroVerifier(t, lengthParameter, random);
		this.lengthParameter = lengthParameter;
	}
	
	/**
	 * Default constructor that chooses default values for the parameters.
	 */
	public SigmaDamgardJurikEncryptedValueVerifier() {
		lengthParameter = 1;
		//Creates the underlying sigmaDamgardJurik object with default parameters.
		sigmaDamgardJurik = new SigmaDamgardJurikEncryptedZeroVerifier(80, lengthParameter, new SecureRandom());
	}
	
	/**
	 * Returns the soundness parameter for this Sigma protocol.
	 * @return t soundness parameter
	 */
	public int getSoundness(){
		//Delegates to the underlying sigmaDamgardJurik verifier.
		return sigmaDamgardJurik.getSoundness();
	}

	/**
	 * Converts the input to the underlying object input.
	 * @param input MUST be an instance of SigmaDJEncryptedValueInput.
	 * @throws IllegalArgumentException if input is not an instance of SigmaDJEncryptedValueInput.
	 */
	public void setInput(SigmaProtocolInput in) {
		/*
		 * Converts the input (n, c, x) to (n, c') where c’ = c*(1+n)^(-x) mod N'.
		 */
		if (!(in instanceof SigmaDJEncryptedValueInput)){
			throw new IllegalArgumentException("the given input must be an instance of SigmaDJEncryptedValueInput");
		}
		SigmaDJEncryptedValueInput input = (SigmaDJEncryptedValueInput) in;
		
		//Get public key, cipher and plaintext.
		DamgardJurikPublicKey pubKey = input.getPublicKey();
		BigIntegerPlainText plaintext = input.getPlaintext();
		BigIntegerCiphertext cipher = input.getCiphertext();
		
		//Convert the cipher c to c' = c*(1+n)^(-x)
		BigInteger n = pubKey.getModulus();
		BigInteger nPlusOne = n.add(BigInteger.ONE);
		
		//calculate N' = n^(s+1).
		BigInteger NTag = n.pow(lengthParameter + 1);
		
		//Calculate (n+1)^(-x)
		BigInteger minusX = plaintext.getX().negate();
		BigInteger multVal = nPlusOne.modPow(minusX, NTag);
		
		//Calculate the ciphertext for DamgardJurikEncryptedZero - c*(n+1)^(-x).
		BigInteger newCipher = cipher.getCipher().multiply(multVal).mod(NTag);
		BigIntegerCiphertext cipherTag = new BigIntegerCiphertext(newCipher);
		
		//Create an input object to the underlying sigmaDamgardJurik verifier.
		SigmaDJEncryptedZeroInput underlyingInput = new SigmaDJEncryptedZeroInput(pubKey, cipherTag);
		sigmaDamgardJurik.setInput(underlyingInput);
		
				
	}
	
	/**
	 * Samples the challenge e <- {0,1}^t
	 */
	public void sampleChallenge(){
		//Delegates to the underlying sigmaDamgardJurik verifier.
		sigmaDamgardJurik.sampleChallenge();
	}
	
	/**
	 * Sets the given challenge.
	 * @param challenge
	 */
	public void setChallenge(byte[] challenge){
		//Delegates to the underlying sigmaDamgardJurik verifier.
		sigmaDamgardJurik.setChallenge(challenge);

	}
	
	/**
	 * Returns the sampled challenge.
	 * @return the challenge.
	 */
	public byte[] getChallenge(){
		//Delegates to the underlying sigmaDamgardJurik verifier.
		return sigmaDamgardJurik.getChallenge();
	}

	/**
	 * Verifies the proof.
	 * @param z second message from prover
	 * @return true if the proof has been verified; false, otherwise.
	 * @throws IllegalArgumentException if the messages of the prover are not an instance of SigmaBIMsg
	 */
	public boolean verify(SigmaProtocolMsg a, SigmaProtocolMsg z) {
		//Delegates to the underlying sigmaDamgardJurik verifier.
		return sigmaDamgardJurik.verify(a, z);
	}
}
