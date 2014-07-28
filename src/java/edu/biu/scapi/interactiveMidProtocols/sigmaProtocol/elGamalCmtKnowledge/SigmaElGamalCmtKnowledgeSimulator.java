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
package edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.elGamalCmtKnowledge;

import java.security.SecureRandom;

import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.SigmaSimulator;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.dlog.SigmaDlogCommonInput;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.dlog.SigmaDlogSimulator;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaCommonInput;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaSimulatorOutput;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;

/**
 * Concrete implementation of Sigma Simulator.<p>
 * This implementation simulates the case that the prover convince a verifier that it knows the value committed to in the commitment (h,c1, c2).<p>
 * 
 * The pseudo code of this protocol can be found in Protocol 1.6 of pseudo codes document at {@link http://crypto.biu.ac.il/scapi/SDK_Pseudocode_SCAPI_V2.0.0.pdf}.<p>
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class SigmaElGamalCmtKnowledgeSimulator implements SigmaSimulator{

	/*	
	  This class uses an instance of SigmaDlogSimulator with:
	  	•	Common parameters (G,q,g) and t
		•	Common input: h (1st element of commitment)
	*/

	private SigmaDlogSimulator dlogSim; //underlying SigmaDlogSimulator to use.
	
	/**
	 * Constructor that gets the underlying DlogGroup, soundness parameter and SecureRandom.
	 * @param dlog
	 * @param t Soundness parameter in BITS.
	 * @param random
	 */
	public SigmaElGamalCmtKnowledgeSimulator(DlogGroup dlog, int t, SecureRandom random){
		
		//Creates the underlying SigmaDlogSimulator object with the given parameters.
		dlogSim = new SigmaDlogSimulator(dlog, t, random);
	}
	
	/**
	 * Constructor that gets a simulator and sets it.<p>
	 * In getSimulator function in SigmaElGamalPrivateKeyProver, the prover needs to create an instance of this class.<p>
	 * The problem is that the prover does not know which Dlog, t and random to give, since they are values of the underlying 
	 * SigmaDlogProver that the prover holds.
	 * Using this constructor, the (ElGamal) prover can get the dlog simulator from the underlying (Dlog) prover and use it to create this object.
	 * 
	 * @param simulator MUST be an instance of SigmaDlogSimulator.
	 * @throws IllegalArgumentException if the given simulator is not an instance of SigmaDlogSimulator.
	 */
	SigmaElGamalCmtKnowledgeSimulator(SigmaSimulator simulator) {
		
		if (!(simulator instanceof SigmaDlogSimulator)){
			throw new IllegalArgumentException("The given simulator is not an instance of SigmaDlogSimulator");
		}
		//Sets the given object as the underlying SigmaDlogSimulator.
		dlogSim = (SigmaDlogSimulator) simulator;
	}
	
	/**
	 * Returns the soundness parameter for this Sigma protocol.
	 * @return t soundness parameter
	 */
	public int getSoundnessParam(){
		return dlogSim.getSoundnessParam();
	}
	
	/**
	 * Computes the simulator computation.
	 * @param input MUST be an instance of SigmaElGamalCTKnowledgeCommonInput.
	 * @param challenge
	 * @return the output of the computation - (a, e, z).
	 * @throws CheatAttemptException if the received challenge's length is not equal to the soundness parameter.
	 * @throws IllegalArgumentException if the given input is not an instance of SigmaElGamalCTKnowledgeCommonInput.
	 */
	public SigmaSimulatorOutput simulate(SigmaCommonInput input, byte[] challenge) throws CheatAttemptException{
		//Converts the input to an input object of the underlying simulator.
		SigmaDlogCommonInput dlogInput = convertInput(input);
		
		//Delegates the computation to the underlying Sigma Dlog prover.
		return dlogSim.simulate(dlogInput, challenge); 
				
	}

	/**
	 * Converts the given input to an input object of the underlying Sigma simulator.
	 * @param input MUST be an instance of SigmaElGamalCTKnowledgeCommonInput.
	 * @return the converted input.
	 * @throws IllegalArgumentException if the given input is not an instance of SigmaElGamalCTKnowledgeCommonInput.
	 */
	private SigmaDlogCommonInput convertInput(SigmaCommonInput input) {
		if (!(input instanceof SigmaElGamalCmtKnowledgeCommonInput)){
			throw new IllegalArgumentException("the given input must be an instance of SigmaElGamalCTKnowledgeCommonInput");
		}
		SigmaElGamalCmtKnowledgeCommonInput params = (SigmaElGamalCmtKnowledgeCommonInput) input;
		
		//Convert the input to match the required SigmaDlogSimulator's input.
		GroupElement h = params.getPublicKey().getH();
		SigmaDlogCommonInput dlogInput = new SigmaDlogCommonInput(h);
		return dlogInput;
	}
	
	/**
	 * Computes the simulator computation.
	 * @param input MUST be an instance of SigmaElGamalCTKnowledgeCommonInput.
	 * @return the output of the computation - (a, e, z).
	 * @throws IllegalArgumentException if the given input is not an instance of SigmaElGamalCTKnowledgeCommonInput.
	 */
	public SigmaSimulatorOutput simulate(SigmaCommonInput input){
		//Converts the input to an input object of the underlying simulator.
		SigmaDlogCommonInput dlogInput = convertInput(input);
		
		//Delegates the computation to the underlying Sigma Dlog simulator.
		return dlogSim.simulate(dlogInput); 
	}

}
