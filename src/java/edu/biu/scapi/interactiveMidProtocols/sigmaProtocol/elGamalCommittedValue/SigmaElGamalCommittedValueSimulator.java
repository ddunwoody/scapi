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
package edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.elGamalCommittedValue;

import java.security.SecureRandom;

import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.SigmaSimulator;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.dh.SigmaDHCommonInput;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.dh.SigmaDHSimulator;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaCommonInput;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaSimulatorOutput;
import edu.biu.scapi.midLayer.ciphertext.ElGamalOnGroupElementCiphertext.ElGamalOnGrElSendableData;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;

/**
 * Concrete implementation of Sigma Simulator.<p>
 * This implementation simulates the case that the prover convince a verifier that the value committed to in the commitment (h,c1, c2) is x.<p>
 * 
 * The pseudo code of this protocol can be found in Protocol 1.7 of pseudo codes document at {@link http://crypto.biu.ac.il/scapi/SDK_Pseudocode_SCAPI_V2.0.0.pdf}.<p>
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class SigmaElGamalCommittedValueSimulator implements SigmaSimulator{

	/*	
	  This class uses an instance of SigmaDHSimulator with:
	  	•	Common parameters (G,q,g) and t
		•	Common input: (g,h,u,v) = (g,h,c1,c2/x)
	*/

	private SigmaDHSimulator dhSim; 	//underlying SigmaDHSimulator to use.
	private DlogGroup dlog;			  	//We need the DlogGroup instance in order to calculate the input for the underlying SigmaDlogProver
	
	/**
	 * Constructor that gets the underlying DlogGroup, soundness parameter and SecureRandom.
	 * @param dlog
	 * @param t Soundness parameter in BITS.
	 * @param random
	 */
	public SigmaElGamalCommittedValueSimulator(DlogGroup dlog, int t, SecureRandom random){
		
		//Creates the underlying SigmaDHSimulator object with the given parameters.
		dhSim = new SigmaDHSimulator(dlog, t, random);
		this.dlog = dlog;
	}
	
	/**
	 * Constructor that gets a simulator and sets it.<p>
	 * In getSimulator function in SigmaElGamalCommittedValueProver, the prover needs to create an instance of this class.<p>
	 * The problem is that the prover does not know which Dlog, t and random to give, since they are values of the underlying 
	 * SigmaDHProver that the prover holds.
	 * Using this constructor, the (ElGamal) prover can get the DH simulator from the underlying (DH) prover and use it to create this object.
	 * 
	 * @param simulator MUST be an instance of SigmaDHSimulator.
	 * @throws IllegalArgumentException if the given simulator is not an instance of SigmaDHSimulator.
	 */
	SigmaElGamalCommittedValueSimulator(SigmaSimulator simulator) {
		
		if (!(simulator instanceof SigmaDHSimulator)){
			throw new IllegalArgumentException("The given simulator is not an instance of SigmaDHSimulator");
		}
		//Sets the given object to the underlying SigmaDHSimulator.
		dhSim = (SigmaDHSimulator) simulator;
	}
	
	/**
	 * Returns the soundness parameter for this Sigma protocol.
	 * @return t soundness parameter
	 */
	public int getSoundnessParam(){
		return dhSim.getSoundnessParam();
	}
	
	/**
	 * Computes the simulator computation with the given challenge.
	 * @param input MUST be an instance of SigmaElGamalCommittedValueCommonInput.
	 * @param challenge
	 * @return the output of the computation - (a, e, z).
	 * @throws CheatAttemptException if the received challenge's length is not equal to the soundness parameter.
	 * @throws IllegalArgumentException if the given input is not an instance of SigmaElGamalCommittedValueCommonInput.
	 */
	public SigmaSimulatorOutput simulate(SigmaCommonInput in, byte[] challenge) throws CheatAttemptException{
		//Convert the input to an input object for the underlying simulator.
		SigmaDHCommonInput dhInput = convertInput(in);
		
		//Delegates the computation to the underlying Sigma DH prover.
		return dhSim.simulate(dhInput, challenge); 
				
	}

	/**
	 * Converts the input to an input object for the underlying simulator.
	 * @param in
	 * @return
	 */
	private SigmaDHCommonInput convertInput(SigmaCommonInput in) {
		if (!(in instanceof SigmaElGamalCommittedValueCommonInput)){
			throw new IllegalArgumentException("the given input must be an instance of SigmaElGamalCommittedValueCommonInput");
		}
		SigmaElGamalCommittedValueCommonInput params = (SigmaElGamalCommittedValueCommonInput) in;
		
		if (!(params.getCommitment() instanceof ElGamalOnGrElSendableData)){
			throw new IllegalArgumentException("the given input must contain an instance of ElGamalOnGrElSendableData");
		}
		
		//Convert input to the underlying DH prover:
		//(g,h,u,v) = (g,h,c1,c2/x).
		GroupElement h = params.getPublicKey().getH();
		//u = c1
		GroupElement u = dlog.reconstructElement(true, ((ElGamalOnGrElSendableData)params.getCommitment()).getCipher1());
		//Calculate v = c2/x = c2*x^(-1)
		GroupElement c2 = dlog.reconstructElement(true, ((ElGamalOnGrElSendableData)params.getCommitment()).getCipher2());
		GroupElement xInv = dlog.getInverse(params.getX());
		GroupElement v = dlog.multiplyGroupElements(c2, xInv);
		SigmaDHCommonInput dhInput = new SigmaDHCommonInput(h, u, v);
		return dhInput;
	}
	
	/**
	 * Computes the simulator computation with a randomly chosen challenge.
	 * @param in MUST be an instance of SigmaElGamalCommittedValueCommonInput.
	 * @return the output of the computation - (a, e, z).
	 * @throws IllegalArgumentException if the given input is not an instance of SigmaElGamalCommittedValueCommonInput.
	 */
	public SigmaSimulatorOutput simulate(SigmaCommonInput in){
		//Convert the input to an input object for the underlying simulator.
		SigmaDHCommonInput dhInput = convertInput(in);
		
		//Delegates the computation to the underlying Sigma DH simulator.
		return dhSim.simulate(dhInput); 
	}


}
