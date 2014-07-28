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
import java.util.Enumeration;
import java.util.Hashtable;

import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.SigmaProverComputation;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.SigmaSimulator;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaCommonInput;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaMultipleMsg;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaProverInput;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaProtocolMsg;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaSimulatorOutput;

/**
 * Concrete implementation of Sigma Protocol prover computation.<p>
 * 
 * This protocol is used for a prover to convince a verifier that at least k out of n statements are true, 
 * where each statement can be proven by an associated Sigma protocol.<p>
 * 
 * The pseudo code of this protocol can be found in Protocol 1.16 of pseudo codes document at {@link http://crypto.biu.ac.il/scapi/SDK_Pseudocode_SCAPI_V2.0.0.pdf}.<p>
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class SigmaORMultipleProverComputation implements SigmaProverComputation{
	
	/*	
	 * Let (ai,ei,zi) denote the steps of a Sigma protocol SigmaI for proving that xi is in LRi 
	 * Let I denote the set of indices for which P has witnesses
	  This class computes the following calculations:
			For every j not in I, SAMPLE a random element ej <- GF[2^t]
			For every j not in I, RUN the simulator on statement xj and challenge ej to get transcript (aj,ej,zj)
			For every i in I, RUN the prover P on statement xi to get first message ai
			SET a=(a1,…,an)
			
			INTERPOLATE the points (0,e) and {(j,ej)} for every j not in I to obtain a degree n-k polynomial Q (s.t. Q(0)=e and Q(j)=ej for every j not in I)
			For every i in I, SET ei = Q(i)
			For every i in I, COMPUTE the response zi to (ai, ei) in SigmaI using input (xi,wi)
			The message is Q,e1,z1,…,en,zn (where by Q we mean its coefficients)
	*/
	
	private Hashtable<Integer, SigmaProverComputation> provers;	// Underlying Sigma protocol's provers to the OR calculation.
	private Hashtable<Integer, SigmaSimulator> simulators;		// Underlying Sigma protocol's simulators to the OR calculation.
	private int len;											// Number of underlying provers.
	private int t;												// Soundness parameter.
	private int k;												//number of witnesses.
	private SecureRandom random;								// The indexes of the statements which the prover knows the witnesses.
	
	private SigmaORMultipleProverInput input;					// Used in computeFirstMsg function.
	
	private byte[][] challenges;								// Will hold the challenges to the underlying provers/simulators.
																// Some will be calculate in sampleRandomValues function and some in compueSecondMsg. 
	
	private Hashtable<Integer, SigmaSimulatorOutput> simulatorsOutput;	// We save this because we calculate it in computeFirstMsg and using 
																	// it after that, in computeSecondMsg
	
	private long[] fieldElements;								//Will hold pointers to the sampled field elements, 
																//we save the pointers to save the creation of the elements again in computeSecondMsg function.
	
	//Initializes the field GF2E with a random irreducible polynomial with degree t.
	private native void initField(int t, int seed);
	
	//Creates random field elements to be the challenges.
	private native byte[][] createRandomFieldElements(int numElements, long[] fieldElements);
	
	//Interpolates the points to get a polynomial.
	private native long interpolate(byte[] e, long[] fieldElements, int[] indexes);
	
	//Calculates the challenges for the statements with the witnesses.
	private native byte[][] getRestChallenges(long polynomial, int[] indexesInI);
	
	//Returns the byteArray of the polynomial coefficients.
	private native byte[][] getPolynomialBytes(long polynomial);
	
	//Deletes the allocated memory of the polynomial and the field elements.
	private native void deletePointers(long polynomial, long[] fieldElements);
	
	/**
	 * Constructor that gets the underlying provers.
	 * @param provers array of SigmaProverComputation, where each object represent a statement 
	 * 		  and the prover wants to prove to the verify that the OR of all statements are true. 
	 * @param t soundness parameter. t MUST be equal to all t values of the underlying provers object.
	 * @throws IllegalArgumentException if the given t is not equal to all t values of the underlying provers object.
	 */
	public SigmaORMultipleProverComputation(Hashtable<Integer, SigmaProverComputation> provers, Hashtable<Integer, SigmaSimulator> simulators, int t, SecureRandom random) {
		//If the given t is different from one of the underlying object's t values, throw exception.
		
		Enumeration<SigmaProverComputation> proversEl = provers.elements();
		while (proversEl.hasMoreElements()){
			if (t != proversEl.nextElement().getSoundnessParam()){
				throw new IllegalArgumentException("the given t does not equal to one of the t values in the underlying provers objects.");
			}
		}
		Enumeration<SigmaSimulator> simulatorsEl = simulators.elements();
		while (simulatorsEl.hasMoreElements()){
			if (t != simulatorsEl.nextElement().getSoundnessParam()){
				throw new IllegalArgumentException("the given t does not equal to one of the t values in the underlying simulators objects.");
			}
		}
		this.provers = provers;
		k = provers.size();
		this.simulators = simulators;
		len = k + simulators.size();
		this.t = t; 
		this.random = random;
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
	 * Sets the inputs for each one of the underlying prover.
	 * @param input MUST be an instance of SigmaORMultipleProverInput.
	 * @throws IllegalArgumentException if input is not an instance of SigmaORMultipleProverInput.
	 * @throws IllegalArgumentException if the number of given inputs is different from the number of underlying provers.
	 */
	private void checkInput(SigmaProverInput in) {
		if (!(in instanceof SigmaORMultipleProverInput)){
			throw new IllegalArgumentException("the given input must be an instance of SigmaORMultipleProverInput");
		}
		input = (SigmaORMultipleProverInput) in;
		
		int inputLen = input.getProversInput().size()+input.getSimulatorsInput().size();
		
		// If number of inputs is not equal to number of provers, throw exception.
		if (inputLen != len) {
			throw new IllegalArgumentException("number of inputs is different from number of underlying provers");
		}
		
		
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
	 * Computes the first message of the protocol.<p>
	 * "For every j not in I, SAMPLE a random element ej <- GF[2^t]<p>
	 *  For every j not in I, RUN the simulator on statement xj and challenge ej to get transcript (aj,ej,zj)<p>
		For every i in I, RUN the prover P on statement xi to get first message ai<p>
		SET a=(a1,…,an)". 
	 * @param input MUST be an instance of SigmaORMultipleInput.
	 * @return SigmaMultipleMsg contains a1, …, am. 
	 * @throws IllegalArgumentException if input is not an instance of SigmaORMultipleInput.
	 * @throws IllegalArgumentException if the number of given inputs is different from the number of underlying provers. 
	 */
	public SigmaProtocolMsg computeFirstMsg(SigmaProverInput in) {
		//Check the given input.
		checkInput(in);
		Hashtable<Integer, SigmaProverInput> proversInput = input.getProversInput();
		Hashtable<Integer, SigmaCommonInput> simulatorsInput = input.getSimulatorsInput();
		
		//Sample random values for this protocol.
		fieldElements = new long[len - k];
		//For every j not in I, sample a random element ej <- GF[2^t]. We sample the random elements in one native call.
		byte[][] ejs = createRandomFieldElements(len - k, fieldElements);
		int index = 0;
		challenges = new byte[len][];
		
		//Set the created challenges to the challenges array in the empty indexes.
		for (int i=0; i<len; i++){
			if (simulators.get(i) != null){
				//in case that the sample element's length is not t, add zeros to its beginning.
				challenges[i] = alignToT(ejs[index]);
				index++; //increase the index of the sampled challenges array.
			}
		}
		
		//Create an array to hold all messages.
		ArrayList<SigmaProtocolMsg> firstMessages = new ArrayList<SigmaProtocolMsg>();
		//Create an array to hold all simaultor's outputs.
		simulatorsOutput = new Hashtable<Integer, SigmaSimulatorOutput>();
		SigmaSimulatorOutput output;
		//Compute all first messages and add them to the array list.
		for (int i = 0; i < len; i++){
			SigmaProverComputation prover = provers.get(i);
			
			//If i in I, call the underlying computeFirstMsg.
			if (prover != null){
				firstMessages.add(prover.computeFirstMsg(proversInput.get(i)));
			//If i not in I, run the simulator for xi.
			} else{
				try {
					output = simulators.get(i).simulate(simulatorsInput.get(i), challenges[i]);
					firstMessages.add(output.getA());
					simulatorsOutput.put(i, output);
				} catch (CheatAttemptException e) {
					// This exception will not be thrown because the length of the challenges is valid.
				}
			}
		}
		//Create a SigmaMultipleMsg with the messages array.
		return new SigmaMultipleMsg(firstMessages);
		
	}

	/**
	 * Computes the second message of the protocol.<p>
	 * "INTERPOLATE the points (0,e) and {(j,ej)} for every j not in I to obtain a degree n-k polynomial Q (s.t. Q(0)=e and Q(j)=ej for every j not in I)<p>
			For every i in I, SET ei = Q(i)<p>
			For every i in I, COMPUTE the response zi to (ai, ei) in Sigmai using input (xi,wi)<p>
			The message is Q,e1,z1,…,en,zn (where by Q we mean its coefficients)".<p>
	 * @param challenge
	 * @return SigmaMultipleMsg contains z1, …, zm.
	 * @throws CheatAttemptException if the received challenge's length is not equal to the soundness parameter.
	 */
	public SigmaProtocolMsg computeSecondMsg(byte[] challenge) throws CheatAttemptException {
		//Create two arrays of indexes. These arrays used to calculate the interpolated polynomial.
		int[] indexesNotInI= new int[len - k];
		int[] indexesInI= new int[k];
		int indexNotInI = 0;
		int indexInI = 0;
		//Fill the arrays with the indexes.
		for (int i = 0; i < len; i++){
			if (provers.get(i) != null){ //prover i has a witness
				indexesInI[indexInI++] = i+1; //i+1 because Q(0) = e.
			} else {
				indexesNotInI[indexNotInI++] = i+1;
			}
		}
		//Interpolate the points (0,e) and {(j,ej)} for every j NOT in I to obtain a degree n-k polynomial Q.
		long polynomial = interpolate(challenge, fieldElements, indexesNotInI);
		
		//Get the rest of the challenges by computing for every i in I, ei = Q(i).
		byte[][] jsInI = getRestChallenges(polynomial, indexesInI);
		int index = 0;
		for(int i=0; i<len; i++){
			if (provers.get(i) != null){
				challenges[i] = alignToT(jsInI[index++]);
			}
		}
		
		//Create an array to hold all messages.
		ArrayList<SigmaProtocolMsg> secondMessages = new ArrayList<SigmaProtocolMsg>();
		
		//Compute all second messages and add them to the array list.
		for (int i = 0; i < len; i++){
			SigmaProverComputation prover = provers.get(i);
			//If i in I, call the underlying computeSecondMsg.
			if (prover != null){	
				secondMessages.add(prover.computeSecondMsg(challenges[i]));
			//If i not in I, get z from the simulator output for xi.
			} else{
				secondMessages.add(simulatorsOutput.get(i).getZ());
			}
		}
		
		//Get the byte array that represent the polynomial
		byte[][] polynomBytes = getPolynomialBytes(polynomial);
		
		//Delete the allocated memory of the polynomial and the field elements.
		deletePointers(polynomial, fieldElements);
		
		//Create a SigmaORMultipleSecondMsg with the messages array.
		return new SigmaORMultipleSecondMsg(polynomBytes, secondMessages, challenges);
		
	}
	
	/**
	 * Returns the simulator that matches this sigma protocol prover.
	 * @return SigmaORMultipleSimulator
	 */
	public SigmaSimulator getSimulator(){
		ArrayList<SigmaSimulator> simulators = new ArrayList<SigmaSimulator>();
		for (int i=0; i < len; i++){
			simulators.add(provers.get(i).getSimulator());
		}
		return new SigmaORMultipleSimulator(simulators, t, random);
	}

	
	static {
		 
		 //load the NTL jni dll
		 System.loadLibrary("NTLJavaInterface");
	}

}
