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
package edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.orTwo;

import java.security.SecureRandom;

import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.SigmaProverComputation;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.SigmaSimulator;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.utility.SigmaProtocolInput;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.utility.SigmaProtocolMsg;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.utility.SigmaSimulatorOutput;

/**
 * Concrete implementation of Sigma Protocol prover computation.
 * 
 * This protocol is used for a prover to convince a verifier that at least one of two statements is true, 
 * where each statement can be proven by an associated Sigma protocol.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class SigmaORTwoProver implements SigmaProverComputation{
	/*	
	  Let (ai,ei,zi) denote the steps of a Sigma protocol SigmaI for proving that xi is in LRi (i=0,1)
	  This class computes the following calculations:
		  	COMPUTE the first message ab in SigmaB, using (xb,w) as input
			SAMPLE a random challenge  e1-b <- {0, 1}^t 
			RUN the simulator M for SigmaI on input (x1-b, e1-b) to obtain (a1-b, e1-b, z1-b)
			The message is (a0,a1); e1-b,z1-b are stored for later.
			SET eb = e XOR e1-b
			COMPUTE the response zb to (ab, eb) in SigmaB using input (xb,w)
			The message is e0,z0,e1,z1

	*/
	
	private SigmaProverComputation[] provers;	//Underlying Sigma protocol provers.
	private int t;								//Soundness parameter.
	private SecureRandom random;
	private int b;								// The bit b such that (xb,w) is in R.
	private byte[] eOneMinusB;					//Sampled challenge for the simulator.
	private SigmaProtocolInput inputOneMinusB;	//input for the underlying Sigma1-b.
	private SigmaProtocolMsg zOneMinusB;		// The output of the simulator.
	
	
	/**
	 * Constructor that gets the underlying provers.
	 * @param provers array of SigmaProverComputation that contains TWO underlying provers.
	 * @param t soundness parameter. t MUST be equal to both t values of the underlying provers object.
	 * @throws IllegalArgumentException if the given t is not equal to both t values of the underlying provers.
	 * @throws IllegalArgumentException if the given provers array does not contains two objects.
	 */
	public SigmaORTwoProver(SigmaProverComputation[] provers, int t, SecureRandom random) {
		if (provers.length != 2){
			throw new IllegalArgumentException("The given provers array must contains two objects.");
		}
		//If the given t is different from one of the underlying object's t values, throw exception.
		if ((t != provers[0].getSoundness()) || (t != provers[1].getSoundness())){
			throw new IllegalArgumentException("The given t does not equal to one of the t values in the underlying provers objects.");
		}
		
		this.provers = provers;
		this.t = t; 
		this.random = random;
	}

	/**
	 * Returns the soundness parameter for this Sigma protocol.
	 * @return t soundness parameter
	 */
	public int getSoundness(){
		return t;
	}

	/**
	 * Sets the inputs for each one of the underlying provers.
	 * @param input MUST be an instance of SigmaORTwoProverInput.
	 * @throws IllegalArgumentException if input is not an instance of SigmaORTwoProverInput.
	 */
	public void setInput(SigmaProtocolInput in) {
		if (!(in instanceof SigmaORTwoProverInput)){
			throw new IllegalArgumentException("The given input must be an instance of SigmaORTwoProverInput");
		}
		SigmaORTwoProverInput input = (SigmaORTwoProverInput) in;
		//Get b such that (xb,w) is in R.
		b = input.getB();
		
		//Save the input to the simulator.
		inputOneMinusB = input.getInputs()[1-b];
		
		
		//Sets the input WITH THE WITNESS to the corresponding prover.
		//The second prover will not be in use so it does not need to set the input.
		provers[b].setInput(input.getInputs()[b]);
	}

	/**
	 * Call the sampleRandomValues function of the prover that has the witness and computes the following line from the protocol:
	 * "SAMPLE a random challenge  e1-b <- {0, 1}^t" for the simulator.
	 */
	public void sampleRandomValues() {
		//Call the sigma WITH THE WITNESS to sample random values.
		//The second prover will not be in use so it does not need to sample values.
		provers[b].sampleRandomValues();
		
		//Create the challenge for the Simulator.
		//Create a new byte array of size t/8, to get the required byte size.
		eOneMinusB = new byte[t/8];
		//fills the byte array with random values.
		random.nextBytes(eOneMinusB);

	}

	/**
	 * Computes the following lines from the protocol:
	 * "COMPUTE the first message ab in SigmaB, using (xb,w) as input
		RUN the simulator M for SigmaI on input (x1-b, e1-b) to obtain (a1-b, e1-b, z1-b)
		The message is (a0,a1); e1-b,z1-b are stored for later". 
	 * @return SigmaORFirstMsg contains a0, a1.  
	 */
	public SigmaProtocolMsg computeFirstMsg() {
		//Compute the first message ab in Sigma b
		SigmaProtocolMsg aB = provers[b].computeFirstMsg();
		//Get the simulator from Sigma 1-b
		SigmaSimulator simulator = provers[1-b].getSimulator();
		//Simulate Sigma 1-b on input (x1-b, e1-b) to obtain (a1-b, e1-b, z1-b), save the output.
		SigmaSimulatorOutput output = null;
		try {
			output = simulator.simulate(inputOneMinusB, eOneMinusB);
		} catch (CheatAttemptException e) {
			// Since the challenge eOneMinusB's size it t, this exception will not be thrown.
		}
		SigmaProtocolMsg aOneMinusB = output.getA();
		//Save the z1-b to the future.
		zOneMinusB = output.getZ();
		
		//Create and return SigmaORTwoFirstMsg with a0, a1.
		SigmaORTwoFirstMsg msg = null;
		if (b == 0){
			msg = new SigmaORTwoFirstMsg(aB, aOneMinusB);
		} else{
			msg = new SigmaORTwoFirstMsg(aOneMinusB, aB);
		}
		return msg;
		
	}

	/**
	 * Computes the following lines from the protocol:
	 * "SET eb = e XOR e1-b
	 *	COMPUTE the response zb to (ab, eb) in SigmaB using input (xb,w)
	 *	The message is e0,z0,e1,z1".
	 * @param challenge
	 * @return SigmaORTwoSecondMsg contains e0,z0,e1,z1.
	 * @throws CheatAttemptException if the received challenge's length is not equal to the soundness parameter.
	 */
	public SigmaProtocolMsg computeSecondMsg(byte[] challenge) throws CheatAttemptException {
		//check the challenge validity.
		if (!checkChallengeLength(challenge)){
			throw new CheatAttemptException("the length of the given challenge is differ from the soundness parameter");
		}
		
		int len = challenge.length;
		//Set eb = e XOR e1-b.
		byte[] eb = new byte[len];
		for (int i=0; i < len; i++){
			eb[i] = (byte) (challenge[i] ^ eOneMinusB[i]);
		}
		
		//Compute the response zb in SigmaB using input (xb,w).
		SigmaProtocolMsg zb = provers[b].computeSecondMsg(eb);
		
		//Create and return SigmaORTwoSecondMsg with z0, e0, z1, e1.
		SigmaORTwoSecondMsg msg = null;
		if (b == 0){
			msg = new SigmaORTwoSecondMsg(zb, eb, zOneMinusB, eOneMinusB);
		} else{
			msg = new SigmaORTwoSecondMsg(zOneMinusB, eOneMinusB, zb, eb);
		}
		return msg;
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
	 * @return SigmaProtocolANDSimulator
	 */
	public SigmaSimulator getSimulator(){
		//Create a simulators array with simulators that matches the underlying provers.
		SigmaSimulator[] simulators = new SigmaSimulator[2];
		simulators[0] = provers[0].getSimulator();
		simulators[1] = provers[1].getSimulator();
		return new SigmaORTwoSimulator(simulators, t, random);
	}
}
