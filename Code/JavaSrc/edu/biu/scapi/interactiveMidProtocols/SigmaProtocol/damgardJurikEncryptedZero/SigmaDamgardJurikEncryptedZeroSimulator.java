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
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.SigmaSimulator;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.utility.SigmaBIMsg;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.utility.SigmaProtocolInput;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.utility.SigmaSimulatorOutput;

/**
 * Concrete implementation of Sigma Simulator.
 * This implementation simulates the case that the prover convince a verifier that a ciphertext is an encryption of 0 (or an Nth power).
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class SigmaDamgardJurikEncryptedZeroSimulator implements SigmaSimulator{
	
	/*	
	  This class computes the following calculations:
		  	SAMPLE a random value z <- Z*n
			COMPUTE a = z^N/c^e mod N’ 
			OUTPUT (a,e,z)
	*/
	
	private int t; 												// soundness parameter in BITS.
	private int lengthParameter;								// length parameter in BITS.
	private SecureRandom random;
	
	/**
	 * Constructor that gets the soundness parameter, length parameter and SecureRandom.
	 * @param t Soundness parameter in BITS.
	 * @param lengthParameter length parameter in BITS.
	 * @param random
	 */
	public SigmaDamgardJurikEncryptedZeroSimulator(int t, int lengthParameter, SecureRandom random) {
		
		this.t = t;
		this.lengthParameter = lengthParameter;
		this.random = random;
	}
	
	/**
	 * Default constructor that chooses default values for the parameters.
	 */
	public SigmaDamgardJurikEncryptedZeroSimulator() {
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
	 * Computes the simulator computation.
	 * @param input MUST be an instance of SigmaDJEncryptedZeroRandomnessInput.
	 * @param challenge
	 * @return the output of the computation - (a, e, z).
	 * @throws CheatAttemptException if the received challenge's length is not equal to the soundness parameter.
	 * @throws IllegalArgumentException if the given input is not an instance of SigmaDJEncryptedZeroRandomnessInput.
	 */
	public SigmaSimulatorOutput simulate(SigmaProtocolInput input, byte[] challenge) throws CheatAttemptException{
		//check the challenge validity.
		if (!checkChallengeLength(challenge)){
			throw new CheatAttemptException("the length of the given challenge is differ from the soundness parameter");
		}
		
		if (!(input instanceof SigmaDJEncryptedZeroInput)){
			throw new IllegalArgumentException("the given input must be an instance of SigmaDJEncryptedZeroRandomnessInput");
		}
		SigmaDJEncryptedZeroInput djInput = (SigmaDJEncryptedZeroInput) input;
		
		BigInteger n = djInput.getPublicKey().getModulus();
		//Check the soundness validity.
		if (!checkSoundness(n)){
			throw new IllegalArgumentException("t must be less than a third of the length of the public key n");
		}
		
		//Sample a random value z <- Z*n
		BigInteger z = BigIntegers.createRandomInRange(BigInteger.ONE, n.subtract(BigInteger.ONE), random);
		
		//Calculate N = n^s and N' = n^(s+1)
		BigInteger N = n.pow(lengthParameter);
		BigInteger NTag = n.pow(lengthParameter + 1);
		BigInteger e = new BigInteger(1, challenge);
		
		//Compute a = z^N/c^e mod N’
		BigInteger zToN = z.modPow(N, NTag);
		BigInteger denominator = djInput.getCiphertext().getCipher().modPow(e, NTag);
		BigInteger denomInv = denominator.modInverse(NTag);
		BigInteger a = zToN.multiply(denomInv).mod(NTag);
		
		//Output (a,e,z).
		return new SigmaDJEncryptedZeroSimulatorOutput(new SigmaBIMsg(a), challenge, new SigmaBIMsg(z));
				
	}
	
	/**
	 * Computes the simulator computation.
	 * @param input MUST be an instance of SigmaDJEncryptedZeroRandomnessInput.
	 * @return the output of the computation - (a, e, z).
	 * @throws IllegalArgumentException if the given input is not an instance of SigmaDJEncryptedZeroRandomnessInput.
	 */
	public SigmaSimulatorOutput simulate(SigmaProtocolInput input){
		//Create a new byte array of size t/8, to get the required byte size.
		byte[] e = new byte[t/8];
		//Fill the byte array with random values.
		random.nextBytes(e);
		//Call the other simulate function with the given input and the samples e.
		try {
			return simulate(input, e);
		} catch (CheatAttemptException e1) {
			//will not occur since the challenge length is valid.
		}
		return null;
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
	 * Checks if the given challenge length is equal to the soundness parameter.
	 * @return true if the challenge length is t; false, otherwise. 
	 */
	private boolean checkChallengeLength(byte[] challenge){
		//If the challenge's length is equal to t, return true. else, return false.
		return (challenge.length == (t/8) ? true : false);
	}
}
