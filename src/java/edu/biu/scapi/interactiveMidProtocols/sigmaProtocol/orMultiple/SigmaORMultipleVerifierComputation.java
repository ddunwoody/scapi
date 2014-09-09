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
package edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.orMultiple;

import java.security.SecureRandom;
import java.util.ArrayList;

import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.SigmaVerifierComputation;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaCommonInput;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaMultipleMsg;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaProtocolMsg;

/**
 * Concrete implementation of Sigma Protocol verifier computation.<p>
 * 
 * This protocol is used for a prover to convince a verifier that at least k out of n statements is true, 
 * where each statement can be proven by an associated Sigma protocol.<p>
 * 
 * The pseudo code of this protocol can be found in Protocol 1.16 of pseudo codes document at {@link http://crypto.biu.ac.il/scapi/SDK_Pseudocode_SCAPI_V2.0.0.pdf}.<p>
 * 
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class SigmaORMultipleVerifierComputation implements SigmaVerifierComputation{

	/*	
	  Let (ai,ei,zi) denote the steps of a Sigma protocol Sigmai for proving that xi is in LRi 
	  This class computes the following calculations:
		WAIT for messages a1,…,an
		SAMPLE a single random challenge  e <- GF[2^t]
		
		ACC IFF Q is of degree n-k AND Q(i)=ei for all i=1,…,n AND Q(0)=e, and the verifier output on (ai,ei,zi) for all i=1,…,n is ACC
       
	*/
	
	private ArrayList<SigmaVerifierComputation> verifiers;	// Underlying Sigma protocol verifiers to the OR calculation.
	private int len;										// Number of underlying verifiers.
	private byte[] e;										// The challenge.
	private int t;											// Soundness parameter.
	private long challengePointer;							// Pointer to the sampled challenge element.
	private int k;											// Number of true statements.
	
	
	//Initializes the field GF2E with a random irreducible polynomial with degree t.
	private native void initField(int t, int seed);
	
	//Samples the challenge as a field element.
	private native byte[] sampleChallenge(long[] pointer);
	
	//Checks if Q is of degree n-k AND Q(i)=ei for all i=1,…,n AND Q(0)=e. This function also deletes the allocated memory.
	private native boolean checkPolynomialValidity(byte[][] polynomial, int k, long challengePointer, byte[][] challenges);
	
	//Sets the given challenge in the field.
	private native void setChallenge(long [] pointer, byte[] challenge);
	
	/**
	 * Constructor that gets the underlying verifiers.
	 * @param verifiers array of SigmaVerifierComputation, where each object represent a statement 
	 * 		  and the prover wants to convince a verifier that at least k out of n statements is true.
	 * @param t soundness parameter. t MUST be equal to all t values of the underlying verifiers object.
	 * @param random source of randomness
	 * @throws IllegalArgumentException if the given t is not equal to all t values of the underlying verifiers object.
	 */
	public SigmaORMultipleVerifierComputation(ArrayList<SigmaVerifierComputation> verifiers, int t, SecureRandom random) {
		//If the given t is different from one of the underlying object's t values, throw exception.
		for (int i = 0; i < verifiers.size(); i++){
			if (t != verifiers.get(i).getSoundnessParam()){
				throw new IllegalArgumentException("the given t does not equal to one of the t values in the underlying verifiers objects.");
			}
		}
		this.verifiers = verifiers;
		len = verifiers.size();
		this.t = t; 
		
		//Initialize the field GF2E with a random irreducible polynomial with degree t.
		initField(t, random.nextInt());
	}
	
	/**
	 * Returns the soundness parameter for this Sigma protocol.
	 * @return t soundness parameter
	 */
	public int getSoundnessParam(){
		return t;
	}


	/**
	 * Sets the inputs for each one of the underlying verifier.
	 * @param input MUST be an instance of SigmaORMultipleCommonInput.
	 * @throws IllegalArgumentException if input is not an instance of SigmaORMultipleCommonInput.
	 * @throws IllegalArgumentException if the number of given inputs is different from the number of underlying verifier.
	 */
	private void checkInput(SigmaCommonInput in) {
		if (!(in instanceof SigmaORMultipleCommonInput)){
			throw new IllegalArgumentException("the given input must be an instance of SigmaORMultipleCommonInput");
		}
		SigmaORMultipleCommonInput input = (SigmaORMultipleCommonInput) in;
		int inputLen = input.getInputs().size();
		
		// If number of inputs is not equal to number of verifiers, throw exception.
		if (inputLen != len) {
			throw new IllegalArgumentException("number of inputs is different from number of underlying verifiers.");
		}
		
		this.k = input.getK();
	}
	
	/**
	 * Samples the challenge of the protocol.<p>
	 * 	"SAMPLE a single random challenge  e <- GF[2^t]".
	 */
	public void sampleChallenge(){
		//Call the native function to sample a field element.
		long[] pointer = new long[2];
		//The pointer to the sampled challenge will be in the first cell of the array. We send array from technical reasons.
		e = sampleChallenge(pointer);
		e = alignToT(e);
		challengePointer = pointer[0];
	}
	
	/**
	 * Align the given array to t length. Adds zeros in the beginning.
	 * @param array to align
	 * @return the aligned array.
	 */
	private byte[] alignToT(byte[] array) {
		byte[] alignArr = new byte[t/8];
		int len = array.length;
		//in case the array is not aligned, add zeros.
		if (len < t/8){
			int diff = t/8 - len; //Number of bytes to fill with zeros.
			int index = 0;
			// NTL converts byte array to polynomial in the following way:
			// x = sum(p[i]*X^(8*i), i = 0..n-1)
			// This means that the most left byte in the array is the first degree of the polynomial.
			// So, copy the original array content to the left side of the new array.
			for (int i=0; i<len; i++){
				alignArr[index++] = array[i];
			}
			//Add zeros in the right side of the array
			for (int i=0; i<diff; i++){
				alignArr[index++] = 0;
			}
		} else{
			alignArr = array;
		}
		return alignArr;
		
	}
	
	/**
	 * Sets the given challenge.
	 * @param challenge
	 */
	public void setChallenge(byte[] challenge){
		e = alignToT(challenge);
		//Call the native function to sample a field element.
		long[] pointer = new long[2];
		//The pointer to the sampled challenge will be in the first cell of the array. We send array from technical reasons.
		setChallenge(pointer, challenge);
		challengePointer = pointer[0];
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
	 * 	"ACC IFF Q is of degree n-k AND Q(i)=ei for all i=1,…,n AND Q(0)=e, and the verifier output on (ai,ei,zi) for all i=1,…,n is ACC".
	 * @param input MUST be an instance of SigmaORMultipleCommonInput.
	 * @param a first message from prover
	 * @param z second message from prover
	 * @return true if the proof has been verified; false, otherwise.
	 * @throws IllegalArgumentException if input is not an instance of SigmaORMultipleCommonInput.
	 * @throws IllegalArgumentException if the number of given inputs is different from the number of underlying verifier.
	 * @throws IllegalArgumentException if the first message of the prover is not an instance of SigmaMultipleMsg
	 * @throws IllegalArgumentException if the second message of the prover is not an instance of SigmaORMultipleSecondMsg
	 */
	public boolean verify(SigmaCommonInput in, SigmaProtocolMsg a, SigmaProtocolMsg z) {
		//Checks the given input.
		checkInput(in);
		ArrayList<SigmaCommonInput> verifiersInput = ((SigmaORMultipleCommonInput) in).getInputs();
				
		boolean verified = true;
		
		//If one of the messages is illegal, throw exception.
		if (!(a instanceof SigmaMultipleMsg)){
			throw new IllegalArgumentException("first message must be an instance of SigmaMultipleMsg");
		}
		if (!(z instanceof SigmaORMultipleSecondMsg)){
			throw new IllegalArgumentException("second message must be an instance of SigmaORMultipleSecondMsg");
		}
		SigmaMultipleMsg first = (SigmaMultipleMsg) a; 
		SigmaORMultipleSecondMsg second = (SigmaORMultipleSecondMsg) z; 
		ArrayList<SigmaProtocolMsg> firstMessages = first.getMessages();
		ArrayList<SigmaProtocolMsg> secondMessages = second.getMessages();
		
		byte[][] polynomial = second.getPolynomial();
		byte[][] challenges = second.getChallenges();
		
		//Call native function to check the polynomial validity.
		verified = verified && checkPolynomialValidity(polynomial, k, challengePointer, challenges);
		
		//Compute all verifier checks.
		for (int i = 0; i < len; i++){
			verifiers.get(i).setChallenge(challenges[i]);
			verified = verified && verifiers.get(i).verify(verifiersInput.get(i), firstMessages.get(i), secondMessages.get(i));
		}
		
		//Return true if all verifiers returned true; false, otherwise.
		return verified;	
	}
	
	
	static {
		 
		 //load the NTL jni dll
		 System.loadLibrary("NTLJavaInterface");
	}
}
