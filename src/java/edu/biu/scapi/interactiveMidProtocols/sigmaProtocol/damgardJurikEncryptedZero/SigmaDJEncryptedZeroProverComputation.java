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
package edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.damgardJurikEncryptedZero;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.util.BigIntegers;

import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.generals.ScapiDefaultConfiguration;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.DJBasedSigma;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.SigmaProverComputation;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.SigmaSimulator;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaBIMsg;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaProverInput;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaProtocolMsg;

/**
 * Concrete implementation of Sigma Protocol prover computation.<p>
 * 
 * This protocol is used for a party to prove that a ciphertext is an encryption of 0 (or an Nth power).<p>
 * 
 * The pseudo code of this protocol can be found in Protocol 1.11 of pseudo codes document at {@link http://crypto.biu.ac.il/scapi/SDK_Pseudocode_SCAPI_V2.0.0.pdf}.<p>
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class SigmaDJEncryptedZeroProverComputation implements SigmaProverComputation, DJBasedSigma{

	/*	
	  This class computes the following calculations:
		  	SAMPLE random value s <- Z*n 
			COMPUTE a = s^N mod N’
			COMPUTE z = s*r^e mod n.
	
	*/	
	
	private int t; 									// Soundness parameter in BITS.
	private int lengthParameter;					// Length parameter in BITS.
	private SecureRandom random;
	private SigmaDJEncryptedZeroProverInput input;	// Contains public key n, ciphertext c and the random value used to encrypt.
	private BigInteger n;							// Modulus.
	private BigInteger s;							// The random value chosen in the protocol.
	
	/**
	 * Constructor that gets the soundness parameter, length parameter and SecureRandom.
	 * @param t Soundness parameter in BITS.
	 * @param lengthParameter length parameter in BITS.
	 * @param random
	 */
	public SigmaDJEncryptedZeroProverComputation(int t, int lengthParameter, SecureRandom random) {
		
		doConstruct(t, lengthParameter, random);
	}
	
	/**
	 * Default constructor that chooses default values for the parameters.
	 */
	public SigmaDJEncryptedZeroProverComputation() {
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
		
		this.t = t;
		this.lengthParameter = lengthParameter;
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
	 * Checks the validity of the given soundness parameter.<p>
	 * t must be less than a third of the length of the public key n.
	 * @return true if the soundness parameter is valid; false, otherwise.
	 */
	private boolean checkSoundnessParam(BigInteger modulus){
		//If soundness parameter is not less than a third of the publicKey n, return false.
		int third = modulus.bitLength() / 3;
		if (t >= third){
			return false;
		}
		return true;
	}
	
	

	/**
	 * Computes the first message of the protocol.<p>
	 * "SAMPLE random value s <- Z*n<p>
	 * COMPUTE a = s^N mod N’". 
	 * @param input MUST be an instance of SigmaDJEncryptedZeroProverInput.
	 * @return the computed message
	 * @throws IllegalArgumentException if input is not an instance of SigmaDJEncryptedZeroProverInput.
	 */
	public SigmaProtocolMsg computeFirstMsg(SigmaProverInput input) {
		if (!(input instanceof SigmaDJEncryptedZeroProverInput)){
			throw new IllegalArgumentException("the given input must be an instance of SigmaDJEncryptedZeroProverInput");
		}
		
		BigInteger modulus = ((SigmaDJEncryptedZeroProverInput) input).getCommonParams().getPublicKey().getModulus();
		//Check the soundness validity.
		if (!checkSoundnessParam(modulus)){
			throw new IllegalArgumentException("t must be less than a third of the length of the public key n");
		}
		
		this.input = (SigmaDJEncryptedZeroProverInput) input;
		n = modulus;
		
		//Sample s in Z*n
		s = BigIntegers.createRandomInRange(BigInteger.ONE, n.subtract(BigInteger.ONE), random);
		
		//Calculate N = n^s and N' = n^(s+1)
		BigInteger N = n.pow(lengthParameter);
		BigInteger NTag = n.pow(lengthParameter + 1);
		
		//Compute a = s^N mod N'.
		BigInteger a = s.modPow(N, NTag);
		//Create and return SigmaBIMsg with a.
		return new SigmaBIMsg(a);
	}

	/**
	 * Computes the second message of the protocol.<p>
	 * "COMPUTE z = s*r^e mod n".
	 * @param challenge
	 * @return the computed message.
	 * @throws CheatAttemptException if the received challenge's length is not equal to the soundness parameter.
	 */
	public SigmaProtocolMsg computeSecondMsg(byte[] challenge) throws CheatAttemptException {
		
		//check the challenge validity.
		if (!checkChallengeLength(challenge)){
			throw new CheatAttemptException("the length of the given challenge is differ from the soundness parameter");
		}
		
		//Compute z = (s*r^e) mod n
		BigInteger e = new BigInteger(1, challenge);
		BigInteger rToe = input.getR().modPow(e, n);
		BigInteger z = s.multiply(rToe).mod(n);
		
		//Delete the random value r
		s = BigInteger.ZERO;
		
		//Create and return SigmaBIMsg with z.
		return new SigmaBIMsg(z);
		
	}
	
	/**
	 * Checks if the given challenge length is equal to the soundness parameter.
	 * @return true if the challenge length is t; false, otherwise. 
	 */
	private boolean checkChallengeLength(byte[] challenge){
		//If the challenge's length is equal to t, return true. else, return false.
		return (challenge.length == (t/8) ? true : false);
	}

	/**
	 * Returns the simulator that matches this sigma protocol prover.
	 * @return SigmaDamgardJurikEncryptedZeroSimulator
	 */
	public SigmaSimulator getSimulator(){
		return new SigmaDJEncryptedZeroSimulator(t, lengthParameter, random);
	}
	
}
