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
package edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.pedersenCommittedValue;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;

import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.SigmaSimulator;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.dlog.SigmaDlogInput;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.dlog.SigmaDlogSimulator;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.utility.SigmaProtocolInput;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.utility.SigmaSimulatorOutput;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.dlog.cryptopp.CryptoPpDlogZpSafePrime;
import edu.biu.scapi.primitives.dlog.miracl.MiraclDlogECF2m;

/**
 * Concrete implementation of Sigma Simulator.
 * This implementation simulates the case that the prover convince a verifier that the value committed to in the commitment (h, c) is x.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class SigmaPedersenCommittedValueSimulator implements SigmaSimulator{

	/*	
	  Since c = g^r*h^x, it suffices to prove knowledge of r s.t. g^r = c*h^(-x). This is just a DLOG Sigma protocol.
	  
	  This class uses an instance of SigmaDlogSimulator with:
	  	•	Common parameters (G,q,g) and t
		•	Common input: h’ = c*h^(-x) 
	*/

	private SigmaDlogSimulator dlogSim; 	//underlying SigmaDlogSimulator to use.
	private DlogGroup dlog;					//We need the DlogGroup instance in order to calculate the input for the underlying SigmaDlogVerifier.
	
	/**
	 * Constructor that gets the underlying DlogGroup, soundness parameter and SecureRandom.
	 * @param dlog
	 * @param t Soundness parameter in BITS.
	 * @param random
	 */
	public SigmaPedersenCommittedValueSimulator(DlogGroup dlog, int t, SecureRandom random){
		
		setParameters(dlog, t, random);
	}
	
	/**
	 * Default constructor that chooses default values for the parameters.
	 */
	public SigmaPedersenCommittedValueSimulator() {
		
		try {
			//Create Miracl Koblitz 233 Elliptic curve.
			dlog = new MiraclDlogECF2m("K-233");
		} catch (IOException e) {
			//If there is a problem with the elliptic curves file, create Zp DlogGroup.
			dlog = new CryptoPpDlogZpSafePrime();
		}
		
		setParameters(dlog, 80, new SecureRandom());
	}
	
	private void setParameters(DlogGroup dlog, int t, SecureRandom random) {
		
		//Creates the underlying SigmaDlogSimulator object with the given parameters.
		dlogSim = new SigmaDlogSimulator(dlog, t, random);
		this.dlog = dlog;
	}
	
	/**
	 * Constructor that gets a simulator and sets it.
	 * In getSimulator function in SigmaPedersenCommittedValueProver, the prover needs to create an instance of this class.
	 * The problem is that the prover does not know which t and random to give, since they are values of the underlying 
	 * SigmaDlogProver that the prover holds.
	 * Using this constructor, the (PedersenCommittedValue) prover can get the dlog simulator from the underlying (Dlog) prover and use it to create this object.
	 * 
	 * @param simulator MUST be an instance of SigmaDlogSimulator.
	 * @throws IllegalArgumentException if the given simulator is not an instance of SigmaDlogSimulator.
	 */
	SigmaPedersenCommittedValueSimulator(SigmaSimulator simulator) {
		
		if (!(simulator instanceof SigmaDlogSimulator)){
			throw new IllegalArgumentException("The given simulator is not an instance of SigmaDlogSimulator");
		}
		//Sets the given object to the underlying SigmaDlogSimulator.
		dlogSim = (SigmaDlogSimulator) simulator;
	}
	
	/**
	 * Returns the soundness parameter for this Sigma protocol.
	 * @return t soundness parameter
	 */
	public int getSoundness(){
		return dlogSim.getSoundness();
	}
	
	/**
	 * Computes the simulator computation.
	 * @param input MUST be an instance of SigmaPedersenCommittedValueInput.
	 * @param challenge
	 * @return the output of the computation - (a, e, z).
	 * @throws CheatAttemptException if the received challenge's length is not equal to the soundness parameter.
	 * @throws IllegalArgumentException if the given input is not an instance of SigmaPedersenCommittedValueInput.
	 */
	public SigmaSimulatorOutput simulate(SigmaProtocolInput in, byte[] challenge) throws CheatAttemptException{
		//Convert the given input to the underlying Dlog simulator input.
		SigmaDlogInput underlyingInput = convertInput(in);
		
		//Delegate the computation to the underlying Sigma Dlog simulator.
		return dlogSim.simulate(underlyingInput, challenge); 
				
	}
	
	/**
	 * Computes the simulator computation.
	 * @param input MUST be an instance of SigmaPedersenCommittedValueInput.
	 * @return the output of the computation - (a, e, z).
	 * @throws IllegalArgumentException if the given input is not an instance of SigmaPedersenCommittedValueInput.
	 */
	public SigmaSimulatorOutput simulate(SigmaProtocolInput in){
		//Convert the given input to the underlying Dlog simulator input.
		SigmaDlogInput underlyingInput = convertInput(in);
		
		//Delegate the computation to the underlying Sigma Dlog simulator.
		return dlogSim.simulate(underlyingInput); 
	}
	
	/**
	 * Converts the given input to the underlying Dlog simulator input.
	 * @param in input to convert MUST be an instance of SigmaPedersenCommittedValueInput
	 * @return the converted input
	 * @throws IllegalArgumentException if the given input is not an instance of SigmaPedersenCommittedValueInput.
	 */
	private SigmaDlogInput convertInput(SigmaProtocolInput in) {
		//If the given input is not an instance of SigmaPedersenCommittedValueInput throw exception
		if (!(in instanceof SigmaPedersenCommittedValueInput)){
			throw new IllegalArgumentException("the given input must be an instance of SigmaPedersenCommittedValueInput");
		}
		SigmaPedersenCommittedValueInput input = (SigmaPedersenCommittedValueInput) in;
		
		//Convert the input to the underlying Dlog prover. h’ = c*h^(-x).
		BigInteger minusX = dlog.getOrder().subtract(input.getX());
		GroupElement hToX = dlog.exponentiate(input.getH(), minusX);
		GroupElement c = dlog.reconstructElement(true, input.getCommitment().getC());
		GroupElement hTag = dlog.multiplyGroupElements(c, hToX);
		
		//Create and return the input instance with the computes h'.
		SigmaDlogInput underlyingInput = new SigmaDlogInput(hTag);
		return underlyingInput;
	}

}
