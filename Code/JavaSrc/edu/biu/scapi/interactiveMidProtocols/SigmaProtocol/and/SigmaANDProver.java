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
package edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.and;

import java.security.SecureRandom;
import java.util.ArrayList;

import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.SigmaProverComputation;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.SigmaSimulator;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.utility.SigmaMultipleMsg;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.utility.SigmaProtocolInput;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.utility.SigmaProtocolMsg;

/**
 * Concrete implementation of Sigma Protocol prover computation.
 * 
 * This protocol is used for a prover to convince a verifier that the AND of any number of statements are true, 
 * where each statement can be proven by an associated Sigma protocol.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class SigmaANDProver implements SigmaProverComputation{

	/*	
	  This class computes the following calculations:
		  	COMPUTE all first prover messages a1,…,am
			COMPUTE all second prover messages z1,…,zm
	*/
	
	private ArrayList<SigmaProverComputation> provers;	// Underlying Sigma protocol's provers to the AND calculation.
	private int len;									// number of underlying provers.
	private int t;										//Soundness parameter.
	private SecureRandom random;
	
	/**
	 * Constructor that gets the underlying provers.
	 * @param provers array of SigmaProverComputation, where each object represent a statement 
	 * 		  and the prover wants to prove to the verify that the AND of all statements are true. 
	 * @param t soundness parameter. t MUST be equal to all t values of the underlying provers object.
	 * @throws IllegalArgumentException if the given t is not equal to all t values of the underlying provers object.
	 */
	public SigmaANDProver(ArrayList<SigmaProverComputation> provers, int t, SecureRandom random) {
		//If the given t is different from one of the underlying object's t values, throw exception.
		for (int i = 0; i < provers.size(); i++){
			if (t != provers.get(i).getSoundness()){
				throw new IllegalArgumentException("the given t does not equal to one of the t values in the underlying provers objects.");
			}
		}
		this.provers = provers;
		len = provers.size();
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
	 * Sets the inputs for each one of the underlying prover.
	 * @param input MUST be an instance of SigmaANDInput.
	 * @throws IllegalArgumentException if input is not an instance of SigmaANDInput.
	 * @throws IllegalArgumentException if the number of given inputs is different from the number of underlying provers.
	 */
	public void setInput(SigmaProtocolInput in) {
		if (!(in instanceof SigmaANDInput)){
			throw new IllegalArgumentException("the given input must be an instance of SigmaANDInput");
		}
		SigmaANDInput input = (SigmaANDInput) in;
		ArrayList<SigmaProtocolInput> proversInput = input.getInputs();
		int inputLen = proversInput.size();
		
		// If number of inputs is not equal to number of provers, throw exception.
		if (inputLen != len) {
			throw new IllegalArgumentException("number of inputs is different from number of underlying provers.");
		}
		
		//Sets the input to each underlying prover.
		for (int i = 0; i < len; i++){
			provers.get(i).setInput(proversInput.get(i));
		}
	}

	/**
	 * Call the sampleRandomVelues function in each of the underlying provers.
	 */
	public void sampleRandomValues() {
		
		for (int i = 0; i < len; i++){
			provers.get(i).sampleRandomValues();
		}
	}

	/**
	 * Computes the following line from the protocol:
	 * "COMPUTE all first prover messages a1,…,am". 
	 * @return SigmaANDMsg contains a1, …, am.  
	 */
	public SigmaProtocolMsg computeFirstMsg() {
		//Create an array to hold all messages.
		ArrayList<SigmaProtocolMsg> firstMessages = new ArrayList<SigmaProtocolMsg>();
		
		//Compute all first messages and add them to the array list.
		for (int i = 0; i < len; i++){
			firstMessages.add(provers.get(i).computeFirstMsg());
		}
		//Create a SigmaANDMsg with the messages array.
		return new SigmaMultipleMsg(firstMessages);
		
	}

	/**
	 * Computes the following line from the protocol:
	 * "COMPUTE all second prover messages z1,…,zm".
	 * @param challenge
	 * @return SigmaANDMsg contains z1, …, zm.
	 * @throws CheatAttemptException if the received challenge's length is not equal to the soundness parameter.
	 */
	public SigmaProtocolMsg computeSecondMsg(byte[] challenge) throws CheatAttemptException {
		
		//Create an array to hold all messages.
		ArrayList<SigmaProtocolMsg> secondMessages = new ArrayList<SigmaProtocolMsg>();
		//Compute all second messages and add them to the array list.
		for (int i = 0; i < len; i++){
			secondMessages.add(provers.get(i).computeSecondMsg(challenge));
		}
		
		//Create a SigmaANDMsg with the messages array.
		return new SigmaMultipleMsg(secondMessages);
		
	}
	
	/**
	 * Returns the simulator that matches this sigma protocol prover.
	 * @return SigmaProtocolANDSimulator
	 */
	public SigmaSimulator getSimulator(){
		ArrayList<SigmaSimulator> simulators = new ArrayList<SigmaSimulator>();
		for (int i=0; i < len; i++){
			simulators.add(provers.get(i).getSimulator());
		}
		return new SigmaANDSimulator(simulators, t, random);
	}

}
