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
package edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.damgardJurikEncryptedZero;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.util.BigIntegers;

import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.DJBasedSigma;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.SigmaProverComputation;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.SigmaSimulator;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.utility.SigmaBIMsg;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.utility.SigmaProtocolInput;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.utility.SigmaProtocolMsg;

/**
 * Concrete implementation of Sigma Protocol prover computation.<p>
 * 
 * This protocol is used for a party to prove that a ciphertext is an encryption of 0 (or an Nth power).
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class SigmaDamgardJurikEncryptedZeroProver implements SigmaProverComputation, DJBasedSigma{

	/*	
	  This class computes the following calculations:
		  	SAMPLE random value s <- Z*n 
			COMPUTE a = s^N mod N’
			COMPUTE z = s*r^e mod n.
	
	*/	
	
	private int t; 												// soundness parameter in BITS.
	private int lengthParameter;								// length parameter in BITS.
	private SecureRandom random;
	private SigmaDJEncryptedZeroProverInput input;	// Contains public key n, ciphertext c and the random value used to encrypt.
	private BigInteger n;
	private BigInteger s;										// The random value chosen in the protocol.
	
	/**
	 * Constructor that gets the soundness parameter, length parameter and SecureRandom.
	 * @param t Soundness parameter in BITS.
	 * @param lengthParameter length parameter in BITS.
	 * @param random
	 */
	public SigmaDamgardJurikEncryptedZeroProver(int t, int lengthParameter, SecureRandom random) {
		
		this.t = t;
		this.lengthParameter = lengthParameter;
		this.random = random;
	}
	
	/**
	 * Default constructor that chooses default values for the parameters.
	 */
	public SigmaDamgardJurikEncryptedZeroProver() {
		this(80, 1, new SecureRandom());
	}
	
	/**
	 * Returns the soundness parameter for this Sigma protocol.
	 * @return t soundness parameter
	 */
	public int getSoundness(){
		return t;
	}
	
	/**
	 * Sets the input for this Sigma protocol
	 * @param input MUST be an instance of SigmaDJEncryptedZeroRandomnessProverInput.
	 * @throws IllegalArgumentException if input is not an instance of SigmaDJEncryptedZeroRandomnessProverInput.
	 */
	public void setInput(SigmaProtocolInput input) {
		if (!(input instanceof SigmaDJEncryptedZeroProverInput)){
			throw new IllegalArgumentException("the given input must be an instance of SigmaDJEncryptedZeroRandomnessProverInput");
		}
		
		BigInteger modulus = ((SigmaDJEncryptedZeroInput) input).getPublicKey().getModulus();
		//Check the soundness validity.
		if (!checkSoundness(modulus)){
			throw new IllegalArgumentException("t must be less than a third of the length of the public key n");
		}
		
		this.input = (SigmaDJEncryptedZeroProverInput) input;
		n = modulus;
		
	}
	
	/**
	 * Checks the validity of the given soundness parameter.
	 * t must be less than a third of the length of the public key n.
	 * @return true if the soundness parameter is valid; false, otherwise.
	 */
	private boolean checkSoundness(BigInteger modulus){
		//If soundness parameter is not less than a third of the publicKey n, return false.
		int third = modulus.bitLength() / 3;
		if (t >= third){
			return false;
		}
		return true;
	}
	
	/**
	 * Computes the following line from the protocol:
	 * "SAMPLE random value s <- Z*n "
	 */
	public void sampleRandomValues() {
		s = BigIntegers.createRandomInRange(BigInteger.ONE, n.subtract(BigInteger.ONE), random);
	}

	/**
	 * Computes the following line from the protocol:
	 * "COMPUTE a = s^N mod N’". 
	 * @return the computed message
	 */
	public SigmaProtocolMsg computeFirstMsg() {
		
		//Calculate N = n^s and N' = n^(s+1)
		BigInteger N = n.pow(lengthParameter);
		BigInteger NTag = n.pow(lengthParameter + 1);
		
		//Compute a = s^N mod N'.
		BigInteger a = s.modPow(N, NTag);
		//Create and return SigmaGroupElementMsg with a.
		return new SigmaBIMsg(a);
	}

	/**
	 * Computes the following line from the protocol:
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
		return new SigmaDamgardJurikEncryptedZeroSimulator(t, lengthParameter, random);
	}
	
}
