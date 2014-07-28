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

import edu.biu.scapi.generals.ScapiDefaultConfiguration;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.DJBasedSigma;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.SigmaVerifierComputation;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaBIMsg;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaCommonInput;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaProtocolMsg;

/**
 * Concrete implementation of Sigma Protocol verifier computation. <p>
 * 
 * This protocol is used for a party to prove that a ciphertext is an encryption of 0 (or an Nth power).<p>
 * 
 * The pseudo code of this protocol can be found in Protocol 1.11 of pseudo codes document at {@link http://crypto.biu.ac.il/scapi/SDK_Pseudocode_SCAPI_V2.0.0.pdf}.<p>
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class SigmaDJEncryptedZeroVerifierComputation implements SigmaVerifierComputation, DJBasedSigma{

	/*	
	  This class computes the following calculations:
		  	SAMPLE a random challenge  e -< {0, 1}^t 
			ACC IFF c,a,z are relatively prime to n AND z^N = (a*c^e) mod N’
        
	*/
	
	private int t; 								// Soundness parameter in BITS.
	private int lengthParameter;				// Length parameter in BITS.
	private SecureRandom random;
	private byte[] e;							//The challenge.
	private BigInteger n;						//The modulus
	
	/**
	 * Constructor that gets the soundness parameter, length parameter and SecureRandom.
	 * @param t Soundness parameter in BITS.
	 * @param lengthParameter length parameter in BITS.
	 * @param random
	 */
	public SigmaDJEncryptedZeroVerifierComputation(int t, int lengthParameter, SecureRandom random) {
		
		doConstruct(t, lengthParameter, random);
	}
	
	/**
	 * Default constructor that chooses default values for the parameters.
	 */
	public SigmaDJEncryptedZeroVerifierComputation() {
		//read the default statistical parameter used in sigma protocols from a configuration file.
		String statisticalParameter = ScapiDefaultConfiguration.getInstance().getProperty("StatisticalParameter");
		int t = Integer.parseInt(statisticalParameter);
				
		doConstruct(t, 1, new SecureRandom());
	}
	
	private void doConstruct(int t, int lengthParameter, SecureRandom random){
		this.t = t;
		this.lengthParameter = lengthParameter;
		this.random = random;
	}
	
	/**
	 * Checks the validity of the given soundness parameter. <p>
	 * t must be less than a third of the length of the public key n.
	 * @return true if the soundness parameter is valid; false, otherwise.
	 */
	public boolean checkSoundnessParam(BigInteger modulus){
		//If soundness parameter is not less than a third of the publicKey n, throw IllegalArgumentException.
		int third = modulus.bitLength() / 3;
		if (t >= third){
			return false;
		}
		return true;
	}
	
	/**
	 * Returns the soundness parameter for this Sigma protocol.
	 * @return t soundness parameter
	 */
	public int getSoundnessParam(){
		return t;
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
	 * 	"ACC IFF c,a,z are relatively prime to n AND z^N = (a*c^e) mod N’".
	 * @param input MUST be an instance of SigmaDJEncryptedZeroCommonInput.
	 * @param z second message from prover
	 * @return true if the proof has been verified; false, otherwise.
	 * @throws IllegalArgumentException if input is not an instance of SigmaDJEncryptedZeroCommonInput.
	 * @throws IllegalArgumentException if the one of the prover's messages are not an instance of SigmaBIMsg
	 */
	public boolean verify(SigmaCommonInput input, SigmaProtocolMsg a, SigmaProtocolMsg z) {
		if (!(input instanceof SigmaDJEncryptedZeroCommonInput)){
			throw new IllegalArgumentException("the given input must be an instance of SigmaDJEncryptedZeroCommonInput");
		}
		
		SigmaDJEncryptedZeroCommonInput djInput = (SigmaDJEncryptedZeroCommonInput) input;
		n = djInput.getPublicKey().getModulus();
		//Check the soundness validity.
		if (!checkSoundnessParam(n)){
			throw new IllegalArgumentException("t must be less than a third of the length of the public key n");
		}
		
		boolean verified = true;
		
		//If one of the messages is illegal, throw exception.
		if (!(a instanceof SigmaBIMsg)){
			throw new IllegalArgumentException("first message must be an instance of SigmaBIMsg");
		}
		if (!(z instanceof SigmaBIMsg)){
			throw new IllegalArgumentException("second message must be an instance of SigmaBIMsg");
		}
		
		//Get the exponent in the second message from the prover.
		BigInteger zBI = ((SigmaBIMsg) z).getMsg();
		//Get the exponent in the second message from the prover.
		BigInteger aBI = ((SigmaBIMsg) a).getMsg();
		//Get the cipher value.
		BigInteger c = djInput.getCiphertext().getCipher();
		
		//If a is not relatively prime to n, set verified to false.
		verified = verified && (aBI.gcd(n).equals(BigInteger.ONE));
		
		//If z is not relatively prime to n, set verified to false.
		verified = verified && (zBI.gcd(n).equals(BigInteger.ONE));
		
		//If c is not relatively prime to n, set verified to false.
		verified = verified && (c.gcd(n).equals(BigInteger.ONE));
				
		//Calculate N = n^s and N' = n^(s+1)
		BigInteger N = n.pow(lengthParameter);
		BigInteger NTag = n.pow(lengthParameter + 1);
		
		//Calculate z^N mod N' (left side of the equation).
		BigInteger left = zBI.modPow(N, NTag);
		
		//Calculate (a*c^e) mod N’ (left side of the equation).
		//Convert e to BigInteger.
		BigInteger eBI = new BigInteger(1, e);
		BigInteger cToe = c.modPow(eBI, NTag);
		BigInteger right = aBI.multiply(cToe).mod(NTag);
		
		//If left and right sides of the equation are not equal, set verified to false.
		verified = verified && left.equals(right);
		
		e = null; //Delete the random value e.
		
		//Return true if all checks returned true; false, otherwise.
		return verified;	
	}
	
}
