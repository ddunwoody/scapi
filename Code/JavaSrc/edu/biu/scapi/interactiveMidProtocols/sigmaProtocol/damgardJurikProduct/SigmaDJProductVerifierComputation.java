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
package edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.damgardJurikProduct;

import java.math.BigInteger;
import java.security.SecureRandom;

import edu.biu.scapi.generals.ScapiDefaultConfiguration;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.DJBasedSigma;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.SigmaVerifierComputation;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaCommonInput;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaProtocolMsg;

/**
 * Concrete implementation of Sigma Protocol verifier computation. <p>
 * 
 * This protocol is used for a party to prove that 3 ciphertexts c1,c2,c3 are encryptions of values x1,x2,x3 s.t. x1*x2=x3 mod N.<p>
 * 
 * The pseudo code of this protocol can be found in Protocol 1.13 of pseudo codes document at {@link http://crypto.biu.ac.il/scapi/SDK_Pseudocode_SCAPI_V2.0.0.pdf}.<p>
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class SigmaDJProductVerifierComputation implements SigmaVerifierComputation, DJBasedSigma{

	/*	
	  This class computes the following calculations:
		  	SAMPLE a random challenge  e -< {0, 1}^t 
			ACC IFF c1,c2,c3,a1,a2,z1,z2,z3 are relatively prime to n 
				AND c1^e*a1 = (1+n)^z1*z2^N mod N’ 
				AND (c2^z1)/(a2*c3^e) = z3^N mod N’
        
	*/
	
	private int t; 						// Soundness parameter in BITS.
	private int lengthParameter;		// Length parameter in BITS.
	private SecureRandom random;
	private byte[] e;					// The challenge.
	
	/**
	 * Constructor that gets the soundness parameter, length parameter and SecureRandom.
	 * @param t Soundness parameter in BITS.
	 * @param lengthParameter length parameter in BITS.
	 * @param random
	 */
	public SigmaDJProductVerifierComputation(int t, int lengthParameter, SecureRandom random) {
		
		doConstruct(t, lengthParameter, random);
	}
	
	/**
	 * Default constructor that chooses default values for the parameters.
	 */
	public SigmaDJProductVerifierComputation() {
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
	 * Sets the input for this Sigma protocol.
	 * @param input MUST be an instance of SigmaDJProductCommonInput.
	 * @throws IllegalArgumentException if input is not an instance of SigmaDJProductCommonInput.
	 */
	private void checkInput(SigmaCommonInput input) {
		if (!(input instanceof SigmaDJProductCommonInput)){
			throw new IllegalArgumentException("the given input must be an instance of SigmaDJProductInput");
		}
		
		BigInteger modulus = ((SigmaDJProductCommonInput) input).getPublicKey().getModulus();
		// Check the soundness validity.
		if (!checkSoundnessParam(modulus)){
			throw new IllegalArgumentException("t must be less than a third of the length of the public key n");
		}
		
	}
	
	/**
	 * Checks the validity of the given soundness parameter.<p>
	 * t must be less than a third of the length of the public key n.
	 * @return true if the soundness parameter is valid; false, otherwise.
	 */
	private boolean checkSoundnessParam(BigInteger modulus){
		//If soundness parameter is not less than a third of the publicKey n, throw IllegalArgumentException.
		int third = modulus.bitLength() / 3;
		if (t >= third){
			return false;
		}
		return true;
	}
	
	/**
	 * Samples the challenge of the protocol.<p>
	 * 	"SAMPLE a random challenge e<-{0,1}^t".
	 */
	public void sampleChallenge(){
		//Create a new byte array of size t/8, to get the required byte size.
		e = new byte[t/8];
		//fills the byte array with random values.
		random.nextBytes(e);
	}
	
	/**
	 * Sets the given challenge.
	 * @param challenge
	 */
	public void setChallenge(byte[] challenge){
		e = challenge;
	}
	
	/**
	 * Returns the sampled challenge.
	 * @return the challenge.
	 */
	public byte[] getChallenge(){
		return e;
	}

	/**
	 * Computes the verification of the protocol.<p>
	 * 	"ACC IFF c1,c2,c3,a1,a2,z1,z2,z3 are relatively prime to n <p>
				AND c1^e*a1 = (1+n)^z1*z2^N mod N’ <p>
				AND (c2^z1)/(a2*c3^e) = z3^N mod N’".
	 * @param z second message from prover
	 * @return true if the proof has been verified; false, otherwise.
	 * @throws IllegalArgumentException if the first prover message is not an instance of SigmaDJProductFirstMsg
	 * @throws IllegalArgumentException if the second prover message is not an instance of SigmaDJProductSecondMsg
	 */
	public boolean verify(SigmaCommonInput input, SigmaProtocolMsg a, SigmaProtocolMsg z) {
		checkInput(input);
		SigmaDJProductCommonInput djInput = (SigmaDJProductCommonInput) input;
		boolean verified = true;
		
		//If one of the messages is illegal, throw exception.
		if (!(a instanceof SigmaDJProductFirstMsg)){
			throw new IllegalArgumentException("first message must be an instance of SigmaDJProductFirstMsg");
		}
		if (!(z instanceof SigmaDJProductSecondMsg)){
			throw new IllegalArgumentException("second message must be an instance of SigmaDJProductSecondMsg");
		}
		SigmaDJProductFirstMsg firstMsg = (SigmaDJProductFirstMsg) a;
		SigmaDJProductSecondMsg secondMsg = (SigmaDJProductSecondMsg) z;
		
		BigInteger n = djInput.getPublicKey().getModulus();
		
		//Get the ciphertexts values from the input.
		BigInteger c1 = djInput.getC1().getCipher();	
		BigInteger c2 = djInput.getC2().getCipher();	
		BigInteger c3 = djInput.getC3().getCipher();
		
		//Get values from the prover's first message.
		BigInteger a1 = firstMsg.getA1();
		BigInteger a2 = firstMsg.getA2();
				
		//Get values from the prover's first message.
		BigInteger z1 = secondMsg.getZ1();
		BigInteger z2 = secondMsg.getZ2();
		BigInteger z3 = secondMsg.getZ3();
		
		//If one of the values is not relatively prime to n, set verified to false.
		verified = verified && areRelativelyPrime(n, c1, c2, a1, a2, z1, z2, z3);
		
		//Calculate N = n^s and N' = n^(s+1)
		BigInteger N = n.pow(lengthParameter);
		BigInteger NTag = n.pow(lengthParameter + 1);
		//Convert e to BigInteger.
		BigInteger eBI = new BigInteger(1, e);
		
		//Check that c1^e*a1 = (1+n)^z1*z2^N mod N’ 
		BigInteger c1ToE = c1.modPow(eBI, NTag);
		BigInteger left = c1ToE.multiply(a1).mod(NTag);
		BigInteger nPlusOneToZ1 = n.add(BigInteger.ONE).modPow(z1, NTag);
		BigInteger z2ToN = z2.modPow(N, NTag);
		BigInteger right = nPlusOneToZ1.multiply(z2ToN).mod(NTag);
		
		//If left and right sides of the equation are not equal, set verified to false.
		verified = verified && left.equals(right);
		
		//Check that (c2^z1)/(a2*c3^e) = z3^N mod N’
		BigInteger numerator = c2.modPow(z1, NTag);
		BigInteger c3ToE = c3.modPow(eBI, NTag);
		BigInteger denominator = a2.multiply(c3ToE).mod(NTag);
		BigInteger denominatorInv = denominator.modInverse(NTag);
		left = numerator.multiply(denominatorInv).mod(NTag);
		right = z3.modPow(N, NTag);
		
		//If left and right sides of the equation are not equal, set verified to false.
		verified = verified && left.equals(right);
		
		e = null; //Delete the random value e.
		
		//Return true if all checks returned true; false, otherwise.
		return verified;
		
	}

	private boolean areRelativelyPrime(BigInteger n, BigInteger c1,
			BigInteger c2, BigInteger a1, BigInteger a2, BigInteger z1,
			BigInteger z2, BigInteger z3) {
		
		//Check that the ciphertexts are relatively prime to n. 
		if (!(c1.gcd(n).equals(BigInteger.ONE)) || !(c2.gcd(n).equals(BigInteger.ONE)) || !(c2.gcd(n).equals(BigInteger.ONE))){
			return false;
		}
		
		//Check that the first message's values are relatively prime to n. 
		if (!(a1.gcd(n).equals(BigInteger.ONE)) || !(a2.gcd(n).equals(BigInteger.ONE))){
			return false;
		}
		
		//Check that the second message's values are relatively prime to n. 
		if (!(z1.gcd(n).equals(BigInteger.ONE)) || !(z2.gcd(n).equals(BigInteger.ONE)) || !(z3.gcd(n).equals(BigInteger.ONE))){
			return false;
		}
		
		return true;
	}
}
