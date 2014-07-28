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
package edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.orTwo;

import java.security.SecureRandom;

import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.SigmaSimulator;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaCommonInput;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaSimulatorOutput;

/**
 * Concrete implementation of Sigma Simulator.<p>
 * This implementation simulates the case that the prover convince a verifier that at least one of two statements is true, 
 * where each statement can be proven by an associated Sigma protocol.
 * 
 * For more information see Protocol 6.4.1, page 159 of Hazay-Lindell.<P>
 * The pseudo code of this protocol can be found in Protocol 1.15 of pseudo codes document at {@link http://crypto.biu.ac.il/scapi/SDK_Pseudocode_SCAPI_V2.0.0.pdf}.<p>
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class SigmaORTwoSimulator implements SigmaSimulator{

	/*	
	  This class computes the following calculations:
		  	SAMPLE a random e0, 
		  	COMPUTE e1 = e XOR e0 
		  	RUN the Sigma protocol simulator for each protocol with the resulting e0,e1 values.

	*/
	
	private SigmaSimulator[] simulators;			//underlying simulators.
	private int t;									// Soundness parameter.
	private SecureRandom random;
	
	/**
	 * Constructor that gets the underlying simulators.
	 * @param simulators array of SigmaSimulator that contains TWO underlying simulators.
	 * @param t soundness parameter. t MUST be equal to both t values of the underlying simulators object.
	 * @throws IllegalArgumentException if the given t is not equal to both t values of the underlying simulators.
	 * @throws IllegalArgumentException if the given simulators array does not contains two objects.
	 */
	public SigmaORTwoSimulator(SigmaSimulator[] simulators, int t, SecureRandom random) {
		if (simulators.length != 2){
			throw new IllegalArgumentException("The given simulators array must contains two objects.");
		}
		
		//If the given t is different from one of the underlying object's t values, throw exception.
		if ((t != simulators[0].getSoundnessParam()) || (t != simulators[1].getSoundnessParam())){
			throw new IllegalArgumentException("The given t does not equal to one of the t values in the underlying simulators objects.");
		}
				
		this.simulators = simulators;
		this.t = t;
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
	 * Computes the simulator computation with the given challenge.
	 * @param input MUST be an instance of SigmaORTwoCommonInput.
	 * @param challenge
	 * @return the output of the computation - (a, e, z).
	 * @throws CheatAttemptException if the received challenge's length is not equal to the soundness parameter.
	 * @throws IllegalArgumentException if the given input is not an instance of SigmaORTwoCommonInput.
	 */
	public SigmaSimulatorOutput simulate(SigmaCommonInput in, byte[] challenge) throws CheatAttemptException{
		/*
		 * SAMPLE a random e0, 
		 * 	COMPUTE e1 = e XOR e0 
		 * 	RUN the Sigma protocol simulator for each protocol with the resulting e0,e1 values.
		 */
		
		//check the challenge validity.
		if (!checkChallengeLength(challenge)){
			throw new CheatAttemptException("the length of the given challenge is differ from the soundness parameter");
		}
				
		if (!(in instanceof SigmaORTwoCommonInput)){
			throw new IllegalArgumentException("The given input must be an instance of SigmaORTwoCommonInput");
		}
		SigmaORTwoCommonInput input = (SigmaORTwoCommonInput) in;
		
		int len = t/8;
		//Sample a random e0.
		byte[] e0 = new byte[len];
		//Fill the byte array with random values.
		random.nextBytes(e0);
		
		//Set e1 = challenge XOR e0.
		byte[] e1 = new byte[len];
		for (int i=0; i < len; i++){
			e1[i] = (byte) (challenge[i] ^ e0[i]);
		}
		
		
		SigmaSimulatorOutput output0 = simulators[0].simulate(input.getInputs()[0], e0);
		SigmaSimulatorOutput output1 = simulators[1].simulate(input.getInputs()[1], e1);
		
		
		//Create a SigmaORTwo messages from the simulates function's outputs.
		SigmaORTwoFirstMsg a = new SigmaORTwoFirstMsg(output0.getA(), output1.getA());
		SigmaORTwoSecondMsg z = new SigmaORTwoSecondMsg(output0.getZ(), e0, output1.getZ(), e1);
		
		//Output (a,e,z).
		return new SigmaORTwoSimulatorOutput(a, challenge, z);
				
	}
	
	/**
	 * Computes the simulator computation with a randomly chosen challenge.
	 * @param input MUST be an instance of SigmaORTwoCommonInput.
	 * @return the output of the computation - (a, e, z).
	 * @throws IllegalArgumentException if the given input is not an instance of SigmaORTwoCommonInput.
	 */
	public SigmaSimulatorOutput simulate(SigmaCommonInput input){
		//Create a new byte array of size t/8, to get the required byte size.
		byte[] e = new byte[t/8];
		//Fill the byte array with random values.
		random.nextBytes(e);
		//Call the other simulate function with the given input and the sampled e.
		try {
			return simulate(input, e);
		} catch (CheatAttemptException e1) {
			//will not occur since the challenge length is valid.
		}
		return null;
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
