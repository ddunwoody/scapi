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
package edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.and;

import java.security.SecureRandom;
import java.util.ArrayList;

import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.SigmaSimulator;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaCommonInput;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaMultipleMsg;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaProtocolMsg;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaSimulatorOutput;

/**
 * Concrete implementation of Sigma Simulator.<p>
 * This implementation simulates the case that the prover convince a verifier that the AND of any number of statements are true, 
 * where each statement can be proven by an associated Sigma protocol.<p>
 * 
 * The pseudo code of this protocol can be found in Protocol 1.14 of pseudo codes document at {@link http://crypto.biu.ac.il/scapi/SDK_Pseudocode_SCAPI_V2.0.0.pdf}.<p>
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class SigmaANDSimulator implements SigmaSimulator{
	/*	
	  This class computes the following calculations:
		  	SAMPLE random values z1 <- ZN, z2 <- Z*n, z3 <- Z*n
			COMPUTE a1 = (1+n)^z1*(z2^N/c1^e) mod N’ AND a2 = c2^z1/(z3^N*c3^e) mod N’
			OUTPUT (a,e,z) where a = (a1,a2) AND z=(z1,z2,z3)

	*/
	
	private ArrayList<SigmaSimulator> simulators;	// Underlying Sigma protocol's simulators to the AND calculation.
	private int len;								// Number of underlying simulators.
	private int t;									// Soundness parameter.
	private SecureRandom random;
	
	/**
	 * Constructor that gets the underlying simulators.
	 * @param simulators array of SigmaSimulator, where each object represent a statement 
	 * 		  where the prover wants to prove to the verify that that the AND of all statements are true. 
	 * @param t soundness parameter. t MUST be equal to all t values of the underlying simulators object.
	 * @param random source of randomness
	 */
	public SigmaANDSimulator(ArrayList<SigmaSimulator> simulators, int t, SecureRandom random) {
		
		//If the given t is different from one of the underlying object's t values, throw exception.
		for (int i = 0; i < simulators.size(); i++){
			if (t != simulators.get(i).getSoundnessParam()){
				throw new IllegalArgumentException("the given t does not equal to one of the t values in the underlying simulators objects.");
			}
		}
		this.simulators = simulators;
		len = simulators.size();
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
	 * @param input MUST be an instance of SigmaANDCommonInput.
	 * @param challenge
	 * @return the output of the computation - (a, e, z).
	 * @throws CheatAttemptException if the received challenge's length is not equal to the soundness parameter.
	 * @throws IllegalArgumentException if the given input is not an instance of SigmaANDCommonInput.
	 */
	public SigmaSimulatorOutput simulate(SigmaCommonInput input, byte[] challenge) throws CheatAttemptException{
		if (!checkChallengeLength(challenge)){
			throw new CheatAttemptException("the length of the given challenge is differ from the soundness parameter");
		}
		
		if (!(input instanceof SigmaANDCommonInput)){
			throw new IllegalArgumentException("the given input must be an instance of SigmaANDCommonInput");
		}
		SigmaANDCommonInput andInput = (SigmaANDCommonInput) input;
		ArrayList<SigmaCommonInput> simulatorsInput = andInput.getInputs();
		int inputLen = simulatorsInput.size();
		
		// If number of inputs is not equal to number of provers, throw exception.
		if (inputLen != len) {
			throw new IllegalArgumentException("number of inputs is different from number of underlying simulators.");
		}
		
		ArrayList<SigmaProtocolMsg> aOutputs = new ArrayList<SigmaProtocolMsg>();
		ArrayList<SigmaProtocolMsg> zOutputs = new ArrayList<SigmaProtocolMsg>();
		SigmaSimulatorOutput output = null;
		//Run each Sigma protocol simulator with the given challenge.
		for (int i = 0; i < len; i++){
			output = simulators.get(i).simulate(simulatorsInput.get(i), challenge);
			aOutputs.add(output.getA());
			zOutputs.add(output.getZ());
		}
		
		//Create a SigmaMultipleMsg from the simulates function's outputs to create a and z.
		SigmaMultipleMsg a = new SigmaMultipleMsg(aOutputs);
		SigmaMultipleMsg z = new SigmaMultipleMsg(zOutputs);
		
		//Output (a,e,z).
		return new SigmaANDSimulatorOutput(a, challenge, z);
				
	}
	
	/**
	 * Computes the simulator computation with a randomly chosen challenge.
	 * @param input MUST be an instance of SigmaANDCommonInput.
	 * @return the output of the computation - (a, e, z).
	 * @throws IllegalArgumentException if the given input is not an instance of SigmaANDCommonInput.
	 */
	public SigmaSimulatorOutput simulate(SigmaCommonInput input){
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
	 * Checks if the given challenge length is equal to the soundness parameter.
	 * @return true if the challenge length is t; false, otherwise. 
	 */
	private boolean checkChallengeLength(byte[] challenge){
		//If the challenge's length is equal to t, return true. else, return false.
		return (challenge.length == (t/8) ? true : false);
	}
}
