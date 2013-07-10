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
package edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.elGamalCommittedValue;

import java.io.IOException;
import java.security.SecureRandom;

import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.SigmaSimulator;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.dh.SigmaDHInput;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.dh.SigmaDHSimulator;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.dlog.SigmaDlogSimulator;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.utility.SigmaProtocolInput;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.utility.SigmaSimulatorOutput;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.dlog.cryptopp.CryptoPpDlogZpSafePrime;
import edu.biu.scapi.primitives.dlog.miracl.MiraclDlogECF2m;

/**
 * Concrete implementation of Sigma Simulator.
 * This implementation simulates the case that the prover convince a verifier that the value committed to in the commitment (h,c1, c2) is x.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class SigmaElGamalCommittedValueSimulator implements SigmaSimulator{

	/*	
	  This class uses an instance of SigmaDlogSimulator with:
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
		
		setParameters(dlog, t, random);
	}
	
	/**
	 * Default constructor that chooses default values for the parameters.
	 */
	public SigmaElGamalCommittedValueSimulator() {
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
		//Creates the underlying SigmaDlogSimulator object with default parameters.
		dhSim = new SigmaDHSimulator(dlog, t, random);
		this.dlog = dlog;
	}
	
	/**
	 * Constructor that gets a simulator and sets it.
	 * In getSimulator function in SigmaElGamalPrivateKeyProver, the prover needs to create an instance of this class.
	 * The problem is that the prover does not know which Dlog, t and random to give, since they are values of the underlying 
	 * SigmaDlogProver that the prover holds.
	 * Using this constructor, the (ElGamal) prover can get the dlog simulator from the underlying (Dlog) prover and use it to create this object.
	 * 
	 * @param simulator MUST be an instance of SigmaDlogSimulator.
	 * @throws IllegalArgumentException if the given simulator is not an instance of SigmaDlogSimulator.
	 */
	SigmaElGamalCommittedValueSimulator(SigmaSimulator simulator) {
		
		if (!(simulator instanceof SigmaDlogSimulator)){
			throw new IllegalArgumentException("The given simulator is not an instance of SigmaDlogSimulator");
		}
		//Sets the given object to the underlying SigmaDlogSimulator.
		dhSim = (SigmaDHSimulator) simulator;
	}
	
	/**
	 * Returns the soundness parameter for this Sigma protocol.
	 * @return t soundness parameter
	 */
	public int getSoundness(){
		return dhSim.getSoundness();
	}
	
	/**
	 * Computes the simulator computation.
	 * @param input MUST be an instance of SigmaElGamalCommittedValueInput.
	 * @param challenge
	 * @return the output of the computation - (a, e, z).
	 * @throws CheatAttemptException if the received challenge's length is not equal to the soundness parameter.
	 * @throws IllegalArgumentException if the given input is not an instance of SigmaElGamalCommittedValueInput.
	 */
	public SigmaSimulatorOutput simulate(SigmaProtocolInput in, byte[] challenge) throws CheatAttemptException{
		if (!(in instanceof SigmaElGamalCommittedValueInput)){
			throw new IllegalArgumentException("the given input must be an instance of SigmaElGamalCommittedValueInput");
		}
		SigmaElGamalCommittedValueInput input = (SigmaElGamalCommittedValueInput) in;
		
		
		//Conver t input to the underlying DH prover:
		//(g,h,u,v) = (g,h,c1,c2/x).
		GroupElement h = dlog.reconstructElement(true, input.getCommitment().getPublicKey().getC());
		//u = c1
		GroupElement u = dlog.reconstructElement(true, input.getCommitment().getCipherData().getCipher1());
		//Calculate v = c2/x = c2*x^(-1)
		GroupElement c2 = dlog.reconstructElement(true, input.getCommitment().getCipherData().getCipher2());
		GroupElement xInv = dlog.getInverse(input.getX());
		GroupElement v = dlog.multiplyGroupElements(c2, xInv);
		SigmaDHInput dhInput = new SigmaDHInput(h, u, v);
		
		//Delegates the computation to the underlying Sigma Dh prover.
		return dhSim.simulate(dhInput, challenge); 
				
	}
	
	/**
	 * Computes the simulator computation.
	 * @param in MUST be an instance of SigmaElGamalCommittedValueInput.
	 * @return the output of the computation - (a, e, z).
	 * @throws IllegalArgumentException if the given input is not an instance of SigmaElGamalCommittedValueInput.
	 */
	public SigmaSimulatorOutput simulate(SigmaProtocolInput in){
		if (!(in instanceof SigmaElGamalCommittedValueInput)){
			throw new IllegalArgumentException("the given input must be an instance of SigmaElGamalCommittedValueInput");
		}
		SigmaElGamalCommittedValueInput input = (SigmaElGamalCommittedValueInput) in;
		
		
		//Conver t input to the underlying DH prover:
		//(g,h,u,v) = (g,h,c1,c2/x).
		GroupElement h = dlog.reconstructElement(true, input.getCommitment().getPublicKey().getC());
		//u = c1
		GroupElement u = dlog.reconstructElement(true, input.getCommitment().getCipherData().getCipher1());
		//Calculate v = c2/x = c2*x^(-1)
		GroupElement c2 = dlog.reconstructElement(true, input.getCommitment().getCipherData().getCipher2());
		GroupElement xInv = dlog.getInverse(input.getX());
		GroupElement v = dlog.multiplyGroupElements(c2, xInv);
		SigmaDHInput dhInput = new SigmaDHInput(h, u, v);
		
		//Delegates the computation to the underlying Sigma Dh simulator.
		return dhSim.simulate(dhInput); 
	}


}
