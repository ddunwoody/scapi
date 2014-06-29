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
package edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.dhExtended;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;

import edu.biu.scapi.exceptions.InvalidDlogGroupException;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.DlogBasedSigma;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.SigmaVerifierComputation;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaBIMsg;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaCommonInput;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaProtocolMsg;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.dlog.GroupElementSendableData;

/**
 * Concrete implementation of Sigma Protocol verifier computation. <p>
 * 
 * This protocol is used for a prover to convince a verifier that the input tuple (g1,…,gm,h1,…,hm) is an 
 * extended Diffie-Hellman tuple, meaning that there exists a single w in Zq such that hi=gi^w for all i.<p>
 * 
 * The pseudo code of this protocol can be found in Protocol 1.3 of pseudo codes document at {@link http://crypto.biu.ac.il/scapi/SDK_Pseudocode_SCAPI_V2.0.0.pdf}.<p>
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class SigmaDHExtendedVerifierComputation implements SigmaVerifierComputation, DlogBasedSigma{

	/*	
	  This class computes the following calculations:
		  	SAMPLE a random challenge  e <- {0, 1}^t 
			ACC IFF VALID_PARAMS(G,q,g)=TRUE AND all g1,…,gm in G AND for all i=1,…,m it holds that gi^z = ai*hi^e        
              
	*/	
	
	private DlogGroup dlog;					// Underlying DlogGroup.
	private int t; 							//Soundness parameter in BITS.
	private byte[] e;						//The challenge.
	private SecureRandom random;
	
	/**
	 * Constructor that gets the underlying DlogGroup, soundness parameter and SecureRandom.
	 * @param dlog
	 * @param t Soundness parameter in BITS.
	 * @param random
	 * @throws InvalidDlogGroupException if the given dlog is invalid.
	 * @throws IllegalArgumentException if soundness parameter is invalid.
	 */
	public SigmaDHExtendedVerifierComputation(DlogGroup dlog, int t, SecureRandom random) throws InvalidDlogGroupException {
		
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
	 * Samples the chaalenge for this protocol.<p>
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
	 * Computes the protocol's verification.<p>
	 * Computes the following line from the protocol:<p>
	 * 	"ACC IFF VALID_PARAMS(G,q,g)=TRUE AND all g1,…,gm in G AND for all i=1,…,m it holds that gi^z = ai*hi^e".   <p>  
	 * @param input MUST be an instance of SigmaDHExtendedCommonInput.
	 * @param z second message from prover
	 * @return true if the proof has been verified; false, otherwise.
	 * @throws IllegalArgumentException if input is not an instance of SigmaDHExtendedCommonInput.
	 * @throws IllegalArgumentException if the first message of the prover is not an instance of SigmaDHExtendedMsg
	 * @throws IllegalArgumentException if the second message of the prover is not an instance of SigmaBIMsg
	 */
	public boolean verify(SigmaCommonInput input, SigmaProtocolMsg a, SigmaProtocolMsg z) {
		//the first check "ACC IFF VALID_PARAMS(G,q,g)=TRUE" is already done in the constructor.
		
		//Check the input.
		if (!(input instanceof SigmaDHExtendedCommonInput)){
			throw new IllegalArgumentException("the given input must be an instance of SigmaDHExtendedCommonInput");
		}
		
		SigmaDHExtendedCommonInput dhInput = (SigmaDHExtendedCommonInput) input;
		ArrayList<GroupElement> gArray = dhInput.getGArray();
		ArrayList<GroupElement> hArray = dhInput.getHArray();
		
		if (gArray.size() != hArray.size()){
			throw new IllegalArgumentException("the given g and h array are not in the same size");
		}
		
		boolean verified = true;
		
		//If one of the messages is illegal, throw exception.
		if (!(a instanceof SigmaDHExtendedMsg)){
			throw new IllegalArgumentException("first message must be an instance of SigmaDHExtendedMsg");
		}
		if (!(z instanceof SigmaBIMsg)){
			throw new IllegalArgumentException("second message must be an instance of SigmaBIMsg");
		}
		
		
		//Get the g array from the input. 
		int len = gArray.size();
		
		//Verify that each gi is in the DlogGroup.
		for (int i=0; i<len; i++){
			//If gi is not member in the group, set verified to false.
			verified = verified && dlog.isMember(gArray.get(i));
		}
		
		
		//Get the h and a arrays.
		SigmaDHExtendedMsg firstMsg = (SigmaDHExtendedMsg) a;
		ArrayList<GroupElementSendableData> aArray = firstMsg.getArray();
		//Get the exponent in the second message from the prover.
		SigmaBIMsg exponent = (SigmaBIMsg) z;
		//Convert e to BigInteger.
		BigInteger eBI = new BigInteger(1, e);
		GroupElement left, right;
		GroupElement hToe;
		GroupElement aElement;
		
		for (int i=0; i<len; i++){
			//Verify that gi^z = ai*hi^e:
			
			//Compute gi^z (left size of the equation).
			left = dlog.exponentiate(gArray.get(i), exponent.getMsg());
			
			//Compute ai*hi^e (right side of the verify equation).
			//Calculate hi^e.
			hToe = dlog.exponentiate(hArray.get(i), eBI);
			//Calculate a*hi^e.
			aElement = dlog.reconstructElement(true, aArray.get(i));
			right = dlog.multiplyGroupElements(aElement, hToe);
			
			//If left and right sides of the equation are not equal, set verified to false.
			verified = verified && left.equals(right);
		}
		
		e = null; //Delete the random value e.
		
		//Return true if all checks returned true; false, otherwise.
		return verified;
	}
}
