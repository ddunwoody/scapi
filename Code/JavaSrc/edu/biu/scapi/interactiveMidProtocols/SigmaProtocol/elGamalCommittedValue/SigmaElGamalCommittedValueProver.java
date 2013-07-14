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
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.DlogBasedSigma;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.SigmaProverComputation;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.SigmaSimulator;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.dh.SigmaDHProver;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.dh.SigmaDHProverInput;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.utility.SigmaProtocolInput;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.utility.SigmaProtocolMsg;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.dlog.cryptopp.CryptoPpDlogZpSafePrime;
import edu.biu.scapi.primitives.dlog.miracl.MiraclDlogECF2m;

/**
 * Concrete implementation of Sigma Protocol prover computation.
 * 
 * This protocol is used for a committer to prove that the value committed to in the commitment (h,c1, c2) is x.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class SigmaElGamalCommittedValueProver implements SigmaProverComputation, DlogBasedSigma{

	/*	
	  This class uses an instance of SigmaDHProver with:
	  	•	Common parameters (G,q,g) and t
		•	Common input: (g,h,u,v) = (g,h,c1,c2/x)
		•	P’s private input: a value r in Zq such that c1=g^r and c2/x =h^r

	*/	 
	
	private SigmaDHProver sigmaDH;	//underlying SigmaDHProver to use.
	private DlogGroup dlog;			//We need the DlogGroup instance in order to calculate the input for the underlying SigmaDlogProver
	
	/**
	 * Constructor that gets the underlying DlogGroup, soundness parameter and SecureRandom.
	 * @param dlog
	 * @param t Soundness parameter in BITS.
	 * @param random
	 */
	public SigmaElGamalCommittedValueProver(DlogGroup dlog, int t, SecureRandom random) {
		
		setParameters(dlog, t, random);
	}
	
	/**
	 * Default constructor that chooses default values for the parameters.
	 */
	public SigmaElGamalCommittedValueProver() {
		try {
			//Create Miracl Koblitz 233 Elliptic curve.
			dlog = new MiraclDlogECF2m("K-233");
		} catch (IOException e) {
			//If there is a problem with the elliptic curves file, create Zp DlogGroup.
			dlog = new CryptoPpDlogZpSafePrime();
		}
		
		setParameters(dlog, 80, new SecureRandom());
	}
	
	/**
	 * Creates the underlying prover computation and sets the given parameters.
	 * @param dlog
	 * @param t Soundness parameter in BITS.
	 * @param random
	 */
	private void setParameters(DlogGroup dlog, int t, SecureRandom random) {
		//Creates the underlying SigmaDHProver object with the given parameters.
		sigmaDH = new SigmaDHProver(dlog, t, random);
		this.dlog = dlog;
	}
	
	/**
	 * Returns the soundness parameter for this Sigma protocol.
	 * @return t soundness parameter
	 */
	public int getSoundness(){
		//Delegates the computation to the underlying Sigma DH prover.
		return sigmaDH.getSoundness();
	}


	/**
	 * Sets the input for this Sigma protocol
	 * @param input MUST be an instance of SigmaElGamalCommittedValueProverInput.
	 * @throws IllegalArgumentException if input is not an instance of SigmaElGamalCommittedValueProverInput.
	 */
	public void setInput(SigmaProtocolInput in) {
		if (!(in instanceof SigmaElGamalCommittedValueProverInput)){
			throw new IllegalArgumentException("the given input must be an instance of SigmaElGamalCommittedValueProverInput");
		}
		SigmaElGamalCommittedValueProverInput input = (SigmaElGamalCommittedValueProverInput) in;
		
		//Convert input to the underlying DH prover:
		//(g,h,u,v) = (g,h,c1,c2/x).
		GroupElement h = dlog.reconstructElement(true, input.getCommitment().getPublicKey().getC());
		//u = c1
		GroupElement u = dlog.reconstructElement(true, input.getCommitment().getCipherData().getCipher1());
		//Calculate v = c2/x = c2*x^(-1)
		GroupElement c2 = dlog.reconstructElement(true, input.getCommitment().getCipherData().getCipher2());
		GroupElement xInv = dlog.getInverse(input.getX());
		GroupElement v = dlog.multiplyGroupElements(c2, xInv);
		SigmaDHProverInput dhInput = new SigmaDHProverInput(h, u, v, input.getR());
		sigmaDH.setInput(dhInput);
		
	}

	/**
	 * Samples random value r in Zq.
	 */
	public void sampleRandomValues() {
		//Delegates to the underlying Sigma DH prover.
		sigmaDH.sampleRandomValues();
	}

	/**
	 * Computes the first message of the protocol.
	 * @return the computed message
	 */
	public SigmaProtocolMsg computeFirstMsg() {
		//Delegates the computation to the underlying Sigma DH prover.
		return sigmaDH.computeFirstMsg();
	}

	/**
	 * Computes the second message of the protocol.
	 * @param challenge
	 * @return the computed message.
	 * @throws CheatAttemptException if the received challenge's length is not equal to the soundness parameter.
	 */
	public SigmaProtocolMsg computeSecondMsg(byte[] challenge) throws CheatAttemptException {
		//Delegates the computation to the underlying Sigma DH prover.
		return sigmaDH.computeSecondMsg(challenge);
		
	}
	
	/**
	 * Returns the simulator that matches this sigma protocol prover.
	 * @return SigmaElGamalCommittedValueSimulator
	 */
	public SigmaSimulator getSimulator(){
		return new SigmaElGamalCommittedValueSimulator(sigmaDH.getSimulator());
	}

}
