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
package edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.damgardJurikProduct;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.util.BigIntegers;

import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.DJBasedSigma;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.SigmaProverComputation;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.SigmaSimulator;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.utility.SigmaProtocolInput;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.utility.SigmaProtocolMsg;

/**
 * Concrete implementation of Sigma Protocol prover computation.<p>
 * 
 * This protocol is used for a party to prove that 3 ciphertexts c1,c2,c3 are encryptions of values x1,x2,x3 s.t. x1*x2=x3 mod N.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class SigmaDamgardJurikProductProver implements SigmaProverComputation, DJBasedSigma{
	/*	
	  This class computes the following calculations:
		  	SAMPLE random values d <- ZN, rd <- Z*n, rdb <- Z*n 
		  	COMPUTE a1=(1+n)^drd^N mod N’ and a2=(1+n)^(d*x2)rdb^N mod N’ and SET a = (a1,a2)
			COMPUTE z1=e*x1+d mod N, z2 = r1^e*rd mod n, z3=(r2^z1)/(rdb*r3^e) mod n, and SET z=(z1,z2,z3)
	*/	
	
	private int t; 										// soundness parameter in BITS.
	private int lengthParameter;						// length parameter in BITS.
	private SecureRandom random;
	private SigmaDJProductProverInput input;	// Contains n, 3 ciphertexts, 3 plaintexts and 3 random values used to encrypt.
	private BigInteger n;								//modulus
	private BigInteger N, NTag;							//N = n^lengthParameter and N' = n^(lengthParameter+1).
	private BigInteger d, rd, rdb;						// The random value chosen in the protocol.
	
	/**
	 * Constructor that gets the soundness parameter, length parameter and SecureRandom.
	 * @param t Soundness parameter in BITS.
	 * @param lengthParameter length parameter in BITS.
	 * @param random
	 */
	public SigmaDamgardJurikProductProver(int t, int lengthParameter, SecureRandom random) {
		
		this.t = t;
		this.lengthParameter = lengthParameter;
		this.random = random;
	}
	
	/**
	 * Default constructor that chooses default values for the parameters.
	 */
	public SigmaDamgardJurikProductProver() {
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
	 * @param input MUST be an instance of SigmaDJProductRandomnessProverInput.
	 * @throws IllegalArgumentException if input is not an instance of SigmaDJProductRandomnessProverInput.
	 */
	public void setInput(SigmaProtocolInput input) {
		if (!(input instanceof SigmaDJProductProverInput)){
			throw new IllegalArgumentException("the given input must be an instance of SigmaDJProductRandomnessProverInput");
		}
		
		BigInteger modulus = ((SigmaDJProductProverInput) input).getPublicKey().getModulus();
		//Check the soundness validity.
		if (!checkSoundness(modulus)){
			throw new IllegalArgumentException("t must be less than a third of the length of the public key n");
		}
		
		this.input = (SigmaDJProductProverInput) input;
		n = modulus;
		
		//Calculate N = n^s and N' = n^(s+1)
		N = n.pow(lengthParameter);
		NTag = n.pow(lengthParameter + 1);

		
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
	 * "SAMPLE random values d <- ZN, rd <- Z*n, rdb <- Z*n"
	 */
	public void sampleRandomValues() {
		//Sample d <-[0, ..., N-1]
		d = BigIntegers.createRandomInRange(BigInteger.ZERO, N.subtract(BigInteger.ONE), random);
		
		//Sample rd, rdb <-[1, ..., n-1]
		rd = BigIntegers.createRandomInRange(BigInteger.ONE, n.subtract(BigInteger.ONE), random);
		rdb = BigIntegers.createRandomInRange(BigInteger.ONE, n.subtract(BigInteger.ONE), random);
	}

	/**
	 * Computes the following line from the protocol:
	 * "COMPUTE a1 = (1+n)^d*rd^N mod N’ and a2 = ((1+n)^(d*x2))*(rdb^N) mod N’ and SET a = (a1,a2)". 
	 * @return the computed message
	 */
	public SigmaProtocolMsg computeFirstMsg() {
		
		//Calculate 1+n
		BigInteger nPlusOne = n.add(BigInteger.ONE);
		//Calculate (1+n)^d
		BigInteger nPlusOneToD = nPlusOne.modPow(d, NTag);
		//Calculate rd^N
		BigInteger rdToN = rd.modPow(N, NTag);
		//Calculate a1=(1+n)^d*rd^N mod N’
		BigInteger a1 = nPlusOneToD.multiply(rdToN).mod(NTag);
		
		//Calculate (1+n)^(d*x2)
		BigInteger exponent = d.multiply(input.getX2().getX());
		BigInteger nPlusOnePow = nPlusOne.modPow(exponent, NTag);
		//Calculate rdb^N
		BigInteger rdbToN = rdb.modPow(N, NTag);
		//Calculate a2 = ((1+n)^(d*x2))*(rdb^N) mod N’
		BigInteger a2 = nPlusOnePow.multiply(rdbToN).mod(NTag);
		
		//Create and return SigmaDJMsg with a1 and a2.
		return new SigmaDJProductFirstMsg(a1, a2);
		
	}

	/**
	 * Computes the following line from the protocol:
	 * "COMPUTE z1=e^x1+d mod N, z2 = r1^e*rd mod n, z3=(r2^z1)/(rdb*r3^e) mod n, and SET z=(z1,z2,z3)".
	 * @param challenge
	 * @return the computed message.
	 * @throws CheatAttemptException if the received challenge's length is not equal to the soundness parameter.
	 */
	public SigmaProtocolMsg computeSecondMsg(byte[] challenge) throws CheatAttemptException {
		
		//check the challenge validity.
		if (!checkChallengeLength(challenge)){
			throw new CheatAttemptException("the length of the given challenge is differ from the soundness parameter");
		}
		
		//Compute z1 = e*x1+d mod N
		BigInteger e = new BigInteger(1, challenge);
		BigInteger ex1 = e.multiply(input.getX1().getX());
		BigInteger z1 = ex1.add(d).mod(N);
		
		//Compute z2 = r1^e*rd mod n
		BigInteger r1Toe = input.getR1().modPow(e, n);
		BigInteger z2 = r1Toe.multiply(rd).mod(n);
		
		//Compute z3=(r2^z1)/(rdb*r3^e) mod n
		BigInteger numerator = input.getR2().modPow(z1, n);
		BigInteger r3ToE = input.getR3().modPow(e, n);
		BigInteger denominator = rdb.multiply(r3ToE);
		BigInteger denominatorInv = denominator.modInverse(n);
		BigInteger z3 = numerator.multiply(denominatorInv).mod(n);
		
		//Delete the random values
		d = BigInteger.ZERO;
		rd = BigInteger.ZERO;
		rdb = BigInteger.ZERO;
		
		//Create and return SigmaDJProductSecondMsg with z1, z2 and z3.
		return new SigmaDJProductSecondMsg(z1, z2, z3);
		
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
	 * @return SigmaDamgardJurikProductSimulator
	 */
	public SigmaSimulator getSimulator(){
		return new SigmaDamgardJurikProductSimulator(t, lengthParameter, random);
	}
}
