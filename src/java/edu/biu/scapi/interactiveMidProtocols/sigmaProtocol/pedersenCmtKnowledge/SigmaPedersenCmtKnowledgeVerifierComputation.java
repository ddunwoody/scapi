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

import edu.biu.scapi.exceptions.InvalidDlogGroupException;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.DlogBasedSigma;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.SigmaVerifierComputation;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaCommonInput;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaGroupElementMsg;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaProtocolMsg;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;

/**
 * Concrete implementation of Sigma Protocol verifier computation. <p>
 * 
 * This protocol is used for a committer to prove that the value committed to in the commitment (h, c) is x.<p>
 * 
 * The pseudo code of this protocol can be found in Protocol 1.4 of pseudo codes document at {@link http://crypto.biu.ac.il/scapi/SDK_Pseudocode_SCAPI_V2.0.0.pdf}.<p>
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class SigmaPedersenCmtKnowledgeVerifierComputation implements SigmaVerifierComputation, DlogBasedSigma{
	
	/*	
	  This class computes the following calculations:
		  	SAMPLE a random challenge  e <- {0, 1}^t 
			ACC IFF VALID_PARAMS(G,q,g)=TRUE AND h in G AND h^u*g^v=a*c^e.       
	*/
	
	private DlogGroup dlog;							// Underlying DlogGroup.
	private int t; 									//Soundness parameter in BITS.
	private byte[] e;								//The challenge.
	private SecureRandom random;
	
	/**
	 * Constructor that gets the underlying DlogGroup, soundness parameter and SecureRandom.
	 * @param dlog
	 * @param t Soundness parameter in BITS.
	 * @param random
	 * @throws InvalidDlogGroupException if the given DlogGroup is not valid.
	 * @throws IllegalArgumentException if soundness parameter is invalid.
	 */
	public SigmaPedersenCmtKnowledgeVerifierComputation(DlogGroup dlog, int t, SecureRandom random) throws InvalidDlogGroupException {
		
		if(!dlog.validateGroup())
			throw new InvalidDlogGroupException();
		
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
		//If soundness parameter does not satisfy 2^t<q, throw IllegalArgumentException.
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
	 * Samples the challenge for this protocol.<p>
	 * 	"SAMPLE a random challenge e<-{0,1}^t".
	 */
	public void sampleChallenge(){
		//Create a new byte array of size t/8, to get the required byte size.
		e = new byte[t/8];
		//fills the byte array with random values.
		random.nextBytes(e);
	}
	
	/**
	 * Sets the given challenge.
	 * @param challenge
	 */
	public void setChallenge(byte[] challenge){
		e = challenge;
	}
	
	/**
	 * Returns the sampled challenge.
	 * @return the challenge.
	 */
	public byte[] getChallenge(){
		return e;
	}

	/**
	 * Computes the varification of the protocol.<p>
	 * 	"ACC IFF VALID_PARAMS(G,q,g)=TRUE AND h in G AND h^u*g^v=a*c^e".
	 * @param input MUST be an instance of SigmaPedersenCTKnowledgeCommonInput.
	 * @param a first message from prover
	 * @param z second message from prover
	 * @return true if the proof has been verified; false, otherwise.
	 * @throws IllegalArgumentException if input is not an instance of SigmaPedersenCTKnowledgeCommonInput.
	 * @throws IllegalArgumentException if the first message of the prover is not an instance of SigmaGroupElementMsg
	 * @throws IllegalArgumentException if the second message of the prover is not an instance of SigmaPedersenCTKnowledgeMsg
	 */
	public boolean verify(SigmaCommonInput input, SigmaProtocolMsg a, SigmaProtocolMsg z) {
		if (!(input instanceof SigmaPedersenCmtKnowledgeCommonInput)){
			throw new IllegalArgumentException("the given input must be an instance of SigmaPedersenCTKnowledgeCommonInput");
		}
		
		//The first check "ACC IFF VALID_PARAMS(G,q,g)=TRUE" is done in the constructor.
		
		boolean verified = true;
		
		//If one of the messages is illegal, throw exception.
		if (!(a instanceof SigmaGroupElementMsg)){
			throw new IllegalArgumentException("first message must be an instance of SigmaGroupElementMsg");
		}
		if (!(z instanceof SigmaPedersenCmtKnowledgeMsg)){
			throw new IllegalArgumentException("second message must be an instance of SigmaPedersenCTKnowledgeMsg");
		}
		
		SigmaPedersenCmtKnowledgeCommonInput params = (SigmaPedersenCmtKnowledgeCommonInput) input;
		
		//Get the h from the input and verify that it is in the Dlog Group.
		GroupElement h = params.getH();
		
		//If h is not member in the group, set verified to false.
		verified = verified && dlog.isMember(h);
		
		//Get the element of the first message from the prover.
		SigmaGroupElementMsg firstMsg = (SigmaGroupElementMsg) a;
		
		SigmaPedersenCmtKnowledgeMsg secondMsg = (SigmaPedersenCmtKnowledgeMsg) z;
		
		//check that h^u*g^v=a*c^e:
		
		//Compute h^u
		GroupElement hToU = dlog.exponentiate(h, secondMsg.getU());
		//Compute g^v
		GroupElement gToV = dlog.exponentiate(dlog.getGenerator(), secondMsg.getV());
		//compute h^u*g^v (left size of the verify equation)
		GroupElement left = dlog.multiplyGroupElements(hToU, gToV);
		
		//Convert e to BigInteger.
		BigInteger eBI = new BigInteger(1, e);
		//Compute c^e.
		GroupElement c = params.getCommitment();
		GroupElement cToe = dlog.exponentiate(c, eBI);
		//Calculate a*c^e (right side of the verify equation
		GroupElement aElement = dlog.reconstructElement(true, firstMsg.getElement());
		GroupElement right = dlog.multiplyGroupElements(aElement, cToe);
		
		//If left and right sides of the equation are not equal, set verified to false.
		verified = verified && left.equals(right);
		
		e = null; //Delete the random value e.
		
		//Return true if all checks returned true; false, otherwise.
		return verified;	
	}
	

}
