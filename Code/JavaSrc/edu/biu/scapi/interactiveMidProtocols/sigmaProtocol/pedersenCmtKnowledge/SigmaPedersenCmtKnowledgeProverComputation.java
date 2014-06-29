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
package edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.pedersenCmtKnowledge;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.util.BigIntegers;

import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.DlogBasedSigma;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.SigmaProverComputation;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.SigmaSimulator;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaGroupElementMsg;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaProverInput;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaProtocolMsg;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;

/**
 * Concrete implementation of Sigma Protocol prover computation.<p>
 * 
 * This protocol is used for a committer to prove that the value committed to in the commitment (h, c) is x.<P>
 * 
 * The pseudo code of this protocol can be found in Protocol 1.4 of pseudo codes document at {@link http://crypto.biu.ac.il/scapi/SDK_Pseudocode_SCAPI_V2.0.0.pdf}.<p>
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class SigmaPedersenCmtKnowledgeProverComputation implements SigmaProverComputation, DlogBasedSigma{
	
	/*	
	  This class computes the following calculations:
		  	SAMPLE random values alpha, beta <- Zq  
			COMPUTE a = (h^alpha)*(g^beta)
			COMPUTE u = alpha + ex mod q and v = beta + er mod q.
	*/	 
	
	private DlogGroup dlog;								// Underlying DlogGroup.
	private int t; 										// soundness parameter in BITS.
	private SecureRandom random;
	private SigmaPedersenCmtKnowledgeProverInput input;	// Contains h, c, x, r.
	private BigInteger alpha, beta;						//random values used in the protocol.
	
	/**
	 * Constructor that gets the underlying DlogGroup, soundness parameter and SecureRandom.
	 * @param dlog
	 * @param t Soundness parameter in BITS.
	 * @param random
	 * @throws IllegalArgumentException if soundness parameter is invalid.
	 */
	public SigmaPedersenCmtKnowledgeProverComputation(DlogGroup dlog, int t, SecureRandom random) {
		
		//Sets the parameters.
		this.dlog = dlog;
		this.t = t;
		
		//Check the soundness validity.
		if (!checkSoundnessParam()){
			throw new IllegalArgumentException("soundness parameter t does not satisfy 2^t<q");
		}
		
		this.random = random;
	}

	/**
	 * Checks the validity of the given soundness parameter.
	 * @return true if the soundness parameter is valid; false, otherwise.
	 */
	private boolean checkSoundnessParam(){
		//If soundness parameter does not satisfy 2^t<q, return false.
		BigInteger soundness = new BigInteger("2").pow(t);
		BigInteger q = dlog.getOrder();
		if (soundness.compareTo(q) >= 0){
			return false;
		}
		return true;
	}

	/**
	 * Returns the soundness parameter for this Sigma protocol.
	 * @return t soundness parameter
	 */
	public int getSoundnessParam(){
		return t;
	}

	/**
	 * Computes the first message of the protocol.<p>
	 * "SAMPLE random values alpha, beta <- Zq<p>
	 *  COMPUTE a = (h^alpha)*(g^beta)". 
	 * @return the computed message
	 */
	public SigmaProtocolMsg computeFirstMsg(SigmaProverInput in) {
		if (!(in instanceof SigmaPedersenCmtKnowledgeProverInput)){
			throw new IllegalArgumentException("the given input must be an instance of SigmaPedersenCTKnowledgeProverInput");
		}
		this.input = (SigmaPedersenCmtKnowledgeProverInput) in;
		
		//Sample random alpha, beta.
		BigInteger qMinusOne = dlog.getOrder().subtract(BigInteger.ONE);
		alpha = BigIntegers.createRandomInRange(BigInteger.ZERO, qMinusOne, random);
		beta = BigIntegers.createRandomInRange(BigInteger.ZERO, qMinusOne, random);	
		
		//Compute h^alpha
		GroupElement hToAlpha = dlog.exponentiate(input.getCommonParams().getH(), alpha);
		//Compute g^beta
		GroupElement gToBeta = dlog.exponentiate(dlog.getGenerator(), beta);
		//Compute a = (h^alpha)*(g^beta)
		GroupElement a = dlog.multiplyGroupElements(hToAlpha, gToBeta);
		
		//Create and return SigmaGroupElementMsg with a.
		return new SigmaGroupElementMsg(a.generateSendableData());
	}

	/**
	 * Computes the second message of the protocol.<p>
	 * "COMPUTE u = alpha + ex mod q and v = beta + er mod q".
	 * @param challenge
	 * @return the computed message.
	 * @throws CheatAttemptException if the received challenge's length is not equal to the soundness parameter.
	 */
	public SigmaProtocolMsg computeSecondMsg(byte[] challenge) throws CheatAttemptException {
		
		//check the challenge validity.
		if (!checkChallengeLength(challenge)){
			throw new CheatAttemptException("the length of the given challenge is differ from the soundness parameter");
		}
		
		//Compute u = alpha + ex mod q
		BigInteger q = dlog.getOrder();
		BigInteger e = new BigInteger(1, challenge);
		BigInteger ex = (e.multiply(input.getX())).mod(q);
		BigInteger u = alpha.add(ex).mod(q);
		
		//Compute v = beta + er mod q
		BigInteger er = (e.multiply(input.getR())).mod(q);
		BigInteger v = beta.add(er).mod(q);
		
		//Delete the random values alpha, beta
		alpha = BigInteger.ZERO;
		beta = BigInteger.ZERO;
		
		//Create and return SigmaPedersenCTKnowledgeMsg with z.
		return new SigmaPedersenCmtKnowledgeMsg(u, v);
		
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
	 * @return SigmaDlogSimulator
	 */
	public SigmaSimulator getSimulator(){
		return new SigmaPedersenCmtKnowledgeSimulator(dlog, t, random);
	}

}
