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
package edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.dh;

import java.math.BigInteger;
import java.security.SecureRandom;

import edu.biu.scapi.exceptions.InvalidDlogGroupException;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.DlogBasedSigma;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.SigmaVerifierComputation;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaBIMsg;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaCommonInput;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaProtocolMsg;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;

/**
 * Concrete implementation of Sigma Protocol verifier computation. <p>
 * This protocol is used for a prover to convince a verifier that the input tuple (g,h,u,v) 
 * is a Diffie-Hellman tuple.<p>
 * 
 * For more information see Protocol 6.2.4, page 152 of Hazay-Lindell.<p>
 * The pseudo code of this protocol can be found in Protocol 1.2 of pseudo codes document at {@link http://crypto.biu.ac.il/scapi/SDK_Pseudocode_SCAPI_V2.0.0.pdf}.<p>
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class SigmaDHVerifierComputation implements SigmaVerifierComputation, DlogBasedSigma{
	
	/*	
	  This class computes the following calculations:
		  	SAMPLE a random challenge  e <- {0, 1}^t 
			ACC IFF VALID_PARAMS(G,q,g) = TRUE AND h in G AND g^z = au^e  AND h^z = bv^e                 
	*/	
	
	private DlogGroup dlog;			// Underlying DlogGroup.
	private int t; 					//Soundness parameter in BITS.
	private byte[] e;				//The challenge.
	private SecureRandom random;
	
	/**
	 * Constructor that gets the underlying DlogGroup, soundness parameter and SecureRandom.
	 * @param dlog
	 * @param t Soundness parameter in BITS.
	 * @param random
	 * @throws InvalidDlogGroupException if the given dlog is invalid.
	 * @throws IllegalArgumentException if soundness parameter is invalid.
	 */
	public SigmaDHVerifierComputation(DlogGroup dlog, int t, SecureRandom random) throws InvalidDlogGroupException {
		
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
	 * Samples the challenge of the protocol.<P>
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
	 * Computers the protocol's verification.<p>
	 * Computes the following line from the protocol:<p>
	 * 	"ACC IFF VALID_PARAMS(G,q,g) = TRUE AND h in G AND g^z = au^e  AND h^z = bv^e".   <p>  
	 * @param input MUST be an instance of SigmaDHCommonInput.
	 * @param z second message from prover
	 * @return true if the proof has been verified; false, otherwise.
	 * @throws IllegalArgumentException if input is not an instance of SigmaDHCommonInput.
	 * @throws IllegalArgumentException if the first message of the prover is not an instance of SigmaDHMsg
	 * @throws IllegalArgumentException if the second message of the prover is not an instance of SigmaBIMsg
	 */
	public boolean verify(SigmaCommonInput input, SigmaProtocolMsg a, SigmaProtocolMsg z) {
		if (!(input instanceof SigmaDHCommonInput)){
			throw new IllegalArgumentException("the given input must be an instance of SigmaDHCommonInput");
		}
		SigmaDHCommonInput dhInput = (SigmaDHCommonInput) input;
		boolean verified = true;
		
		//If one of the messages is illegal, throw exception.
		if (!(a instanceof SigmaDHMsg)){
			throw new IllegalArgumentException("first message must be an instance of SigmaDHMsg");
		}
		if (!(z instanceof SigmaBIMsg)){
			throw new IllegalArgumentException("second message must be an instance of SigmaBIMsg");
		}
		
		//Get the h from the input and verify that it is in the Dlog Group.
		GroupElement h = (dhInput.getH());
		//If h is not member in the group, set verified to false.
		verified = verified && dlog.isMember(h);
		
		//Get the elements of the first message from the prover.
		SigmaDHMsg firstMsg = (SigmaDHMsg) a;
		GroupElement aElement = dlog.reconstructElement(true, firstMsg.getA());
		GroupElement bElement = dlog.reconstructElement(true, firstMsg.getB());
		
		//Get the exponent in the second message from the prover.
		SigmaBIMsg exponent = (SigmaBIMsg) z;
		
		//Verify that g^z = au^e:
		//Compute g^z (left size of the equation).
		GroupElement left = dlog.exponentiate(dlog.getGenerator(), exponent.getMsg());
		//Compute a*u^e (right side of the verify equation).
		//Convert e to BigInteger.
		BigInteger eBI = new BigInteger(1, e);
		//Calculate u^e.
		GroupElement uToe = dlog.exponentiate(dhInput.getU(), eBI);
		//Calculate a*h^e.
		GroupElement right = dlog.multiplyGroupElements(aElement, uToe);
		//If left and right sides of the equation are not equal, set verified to false.
		verified = verified && left.equals(right);
		
		//Verify that h^z = bv^e:
		//Compute h^z (left size of the equation).
		left = dlog.exponentiate(h, exponent.getMsg());
		//Compute b*v^e (right side of the verify equation).
		//Calculate v^e.
		GroupElement vToe = dlog.exponentiate(dhInput.getV(), eBI);
		//Calculate b*v^e.
		right = dlog.multiplyGroupElements(bElement, vToe);
		//If left and right sides of the equation are not equal, set verified to false.
		verified = verified && left.equals(right);
		
		e = null; //Delete the random value e.
		
		//Return true if all checks returned true; false, otherwise.
		return verified;
	}
}
