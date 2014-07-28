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
package edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.damgardJurikEncryptedValue;

import java.math.BigInteger;
import java.security.SecureRandom;

import edu.biu.scapi.generals.ScapiDefaultConfiguration;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.DJBasedSigma;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.SigmaVerifierComputation;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.damgardJurikEncryptedZero.SigmaDJEncryptedZeroCommonInput;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.damgardJurikEncryptedZero.SigmaDJEncryptedZeroVerifierComputation;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaCommonInput;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaProtocolMsg;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.DamgardJurikPublicKey;
import edu.biu.scapi.midLayer.ciphertext.BigIntegerCiphertext;
import edu.biu.scapi.midLayer.plaintext.BigIntegerPlainText;

/**
 * Concrete implementation of Sigma Protocol verifier computation. <p>
 * 
 * This protocol is used for a party who encrypted a value x to prove that it indeed encrypted x.<p>
 * 
 * The pseudo code of this protocol can be found in Protocol 1.12 of pseudo codes document at {@link http://crypto.biu.ac.il/scapi/SDK_Pseudocode_SCAPI_V2.0.0.pdf}.<p>
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class SigmaDJEncryptedValueVerifierComputation implements SigmaVerifierComputation, DJBasedSigma {

	/*	
	  This class uses an instance of SigmaDamgardJurikEncryptedZeroVerifier with:
	  	•	Common input: (n,c’) where c’=c*(1+n)^(-x) mod N'
	
	*/	
	
	private SigmaDJEncryptedZeroVerifierComputation sigmaDamgardJurik;	//underlying SigmaDamgardJurikVerifier to use.
	private int lengthParameter;										// length parameter in BITS.
	
	
	/**
	 * Constructor that gets the underlying DlogGroup, soundness parameter and SecureRandom.
	 * @param dlog
	 * @param t Soundness parameter in BITS.
	 * @param random
	 */
	public SigmaDJEncryptedValueVerifierComputation(int t, int lengthParameter, SecureRandom random) {
		
		doConstruct(t, lengthParameter, random);
	}
	
	/**
	 * Default constructor that chooses default values for the parameters.
	 */
	public SigmaDJEncryptedValueVerifierComputation() {
		
		//read the default statistical parameter used in sigma protocols from a configuration file.
		String statisticalParameter = ScapiDefaultConfiguration.getInstance().getProperty("StatisticalParameter");
		int t = Integer.parseInt(statisticalParameter);
				
		doConstruct(t, 1, new SecureRandom());
	}
	
	/**
	 * Sets the given parameters.
	 * @param t Soundness parameter in BITS.
	 * @param lengthParameter length parameter in BITS.
	 * @param random
	 */
	private void doConstruct(int t, int lengthParameter, SecureRandom random){
		
		//Creates the underlying sigmaDamgardJurik object with the given parameters.
		sigmaDamgardJurik = new SigmaDJEncryptedZeroVerifierComputation(t, lengthParameter, random);
		this.lengthParameter = lengthParameter;
	}
	
	/**
	 * Returns the soundness parameter for this Sigma protocol.
	 * @return t soundness parameter
	 */
	public int getSoundnessParam(){
		//Delegates to the underlying sigmaDamgardJurik verifier.
		return sigmaDamgardJurik.getSoundnessParam();
	}
	
	/**
	 * Samples the challenge e <- {0,1}^t.
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
	 * @param input MUST be an instance of SigmaDJEncryptedValueCommonInput.
	 * @return true if the proof has been verified; false, otherwise.
	 * @throws IllegalArgumentException if input is not an instance of SigmaDJEncryptedValueCommonInput.
	 * @throws IllegalArgumentException if the messages of the prover are not an instance of SigmaBIMsg
	 */
	public boolean verify(SigmaCommonInput in, SigmaProtocolMsg a, SigmaProtocolMsg z) {
		/*
		 * Converts the input (n, c, x) to (n, c') where c’ = c*(1+n)^(-x) mod N'.
		 */
		if (!(in instanceof SigmaDJEncryptedValueCommonInput)){
			throw new IllegalArgumentException("the given input must be an instance of SigmaDJEncryptedValueCommonInput");
		}
		SigmaDJEncryptedValueCommonInput input = (SigmaDJEncryptedValueCommonInput) in;
		
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
		SigmaDJEncryptedZeroCommonInput underlyingInput = new SigmaDJEncryptedZeroCommonInput(pubKey, cipherTag);
		
		//Delegates to the underlying sigmaDamgardJurik verifier.
		return sigmaDamgardJurik.verify(underlyingInput, a, z);
	}
}
