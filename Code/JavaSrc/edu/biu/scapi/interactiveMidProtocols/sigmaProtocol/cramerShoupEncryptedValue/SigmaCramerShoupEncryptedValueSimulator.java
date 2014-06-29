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
package edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.cramerShoupEncryptedValue;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;

import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.SigmaSimulator;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.dhExtended.SigmaDHExtendedCommonInput;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.dhExtended.SigmaDHExtendedSimulator;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaCommonInput;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaSimulatorOutput;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.CramerShoupPublicKey;
import edu.biu.scapi.midLayer.ciphertext.CramerShoupOnGroupElementCiphertext;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.hash.CryptographicHash;

/**
 * Concrete implementation of Sigma Simulator.<p>
 * This implementation simulates the case that the prover convince a verifier that the value encrypted under Cramer-Shoup in the 
 * ciphertext (u1,u2,e,v) with public-key g1,g2,c,d,h is x. <p>
 * The protocol is for the case that the prover knows the randomness used to encrypt.<p>
 * 
 * The pseudo code of this protocol can be found in Protocol 1.10 of pseudo codes document at {@link http://crypto.biu.ac.il/scapi/SDK_Pseudocode_SCAPI_V2.0.0.pdf}.<p>
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class SigmaCramerShoupEncryptedValueSimulator implements SigmaSimulator{
	
	/*	
	  This class uses an instance of SigmaDHExtendedSimulator with:
	  	•	Common DlogGroup
	  	•	Common input: (g1,g2,g3,g4,h1,h2,h3,h4) = (g1,g2,h,cd^w,u1,u2,e/x,v)
	*/
	
	private SigmaDHExtendedSimulator dhSim; 	//underlying SigmaDHExtendedSimulator to use.
	private DlogGroup dlog;						//We save the dlog because we need it to calculate the input for the underlying Sigma verifier.
	private CryptographicHash hash;					//Underlying hash function that used in the CramerShoup cryptosystem.
	
	
	/**
	 * Constructor that gets the underlying DlogGroup, CryptographicHash, soundness parameter and SecureRandom.
	 * @param dlog DlogGroup used in CramerShoup encryption scheme.
	 * @param hash CryptographicHash used in CramerShoup encryption scheme. 
	 * @param t Soundness parameter in BITS.
	 * @param random
	 */
	public SigmaCramerShoupEncryptedValueSimulator(DlogGroup dlog, CryptographicHash hash, int t, SecureRandom random) {
		
		//Creates the underlying SigmaDHextendedSimulator object with the given parameters.
		dhSim = new SigmaDHExtendedSimulator(dlog, t, random);
		this.dlog = dlog;
		this.hash = hash;
	}
	
	/**
	 * Constructor that gets a simulator and sets it.<p>
	 * In getSimulator function in SigmaCramerShoupEncryptedValueProver, the prover needs to create an instance of this class.<p>
	 * The problem is that the prover does not know which t and random to give, since they are values of the underlying 
	 * SigmaDHExtendedProver that the prover holds.<p>
	 * Using this constructor, the (CramerShoup) prover can get the DHExtended simulator from the underlying (DHExtended) prover 
	 * and use it to create this object.
	 * 
	 * @param simulator MUST be an instance of SigmaDHExtendedSimulator.
	 * @throws IllegalArgumentException if the given simulator is not an instance of SigmaDHExtendedSimulator.
	 */
	SigmaCramerShoupEncryptedValueSimulator(SigmaSimulator simulator) {
		
		if (!(simulator instanceof SigmaDHExtendedSimulator)){
			throw new IllegalArgumentException("The given simulator is not an instance of SigmaDHExtendedSimulator");
		}
		//Sets the given object to the underlying SigmaDHExtendedSimulator.
		dhSim = (SigmaDHExtendedSimulator) simulator;
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
	 * @param input MUST be an instance of SigmaCramerShoupEncryptedValueInput.
	 * @param challenge
	 * @return the output of the computation - (a, e, z).
	 * @throws CheatAttemptException if the received challenge's length is not equal to the soundness parameter.
	 * @throws IllegalArgumentException if input is not the expected.
	 */
	public SigmaSimulatorOutput simulate(SigmaCommonInput in, byte[] challenge) throws CheatAttemptException{
		SigmaDHExtendedCommonInput underlyingInput = checkAndCreateUnderlyingInput(in);
		
		//Delegates the computation to the underlying Sigma DHExtended simulator.
		return dhSim.simulate(underlyingInput, challenge); 
				
	}
	
	/**
	 * Computes the simulator computation with a randomly chosen challenge.
	 * @param input MUST be an instance of SigmaCramerShoupEncryptedValueInput.
	 * @return the output of the computation - (a, e, z).
	 * @throws IllegalArgumentException if input is not the expected.
	 */
	public SigmaSimulatorOutput simulate(SigmaCommonInput in){
		SigmaDHExtendedCommonInput underlyingInput = checkAndCreateUnderlyingInput(in);
		
		//Delegates the computation to the underlying Sigma DHExtended simulator.
		return dhSim.simulate(underlyingInput); 
				
	}

	/**
	 * Checks the given input and creates the input for the underlying DH simulator according to it.
	 * @param in MUST be an instance of SigmaCramerShoupEncryptedValueCommonInput.
	 * @return SigmaDHExtendedInput the input for the underlying simulator.
	 * @throws IllegalArgumentException if input is not the expected.
	 */
	private SigmaDHExtendedCommonInput checkAndCreateUnderlyingInput(SigmaCommonInput in) {
		
		if (!(in instanceof SigmaCramerShoupEncryptedValueCommonInput)){
			throw new IllegalArgumentException("the given input must be an instance of SigmaCramerShoupEncryptedValueCommonInput");
		}
		
		//Gets the input values.
		SigmaCramerShoupEncryptedValueCommonInput input = (SigmaCramerShoupEncryptedValueCommonInput) in;
		CramerShoupPublicKey publicKey = input.getPublicKey();
		CramerShoupOnGroupElementCiphertext cipher = input.getCipher();
		GroupElement x = input.getX();
		
		//Prepare the input for the underlying SigmaDHExtendedSimulator.
		ArrayList<GroupElement> gArray = new ArrayList<GroupElement>();
		ArrayList<GroupElement> hArray = new ArrayList<GroupElement>();
		
		//Converts the given input to the necessary input to the underlying SigmaDHExtendedSimulator.
		//(g1,g2,g3,g4,h1,h2,h3,h4) = (g1,g2,h,cd^w,u1,u2,e/x,v)
		
		//add the input for the gArray:
		gArray.add(publicKey.getGenerator1()); //add g1 = g1.
		gArray.add(publicKey.getGenerator2()); //add g2 = g2.
		gArray.add(publicKey.getH());		   //add g3 = h.
		
		//Compute w = H(u1,u2,e).
		BigInteger q = dlog.getOrder();
		BigInteger w = calcW(cipher.getU1(), cipher.getU2(), cipher.getE()).mod(q);
		//Compute cd^w. such that w = H(u1,u2,e).
		GroupElement dToW = dlog.exponentiate(publicKey.getD(), w);
		GroupElement g4 = dlog.multiplyGroupElements(publicKey.getC(), dToW);
		gArray.add(g4);		   				   //add g4 = cd^w.
		
		//add the input for the hArray:
		hArray.add(cipher.getU1());			   //add h1 = u1.
		hArray.add(cipher.getU2());			   //add h2 = u2.
		//Compute e/x = e*x^(-1)
		GroupElement xInverse = dlog.getInverse(x);
		GroupElement h3 = dlog.multiplyGroupElements(cipher.getE(), xInverse);
		hArray.add(h3);			   			   //add h3 = e/x.
		hArray.add(cipher.getV());			   //add h4 = v.
		
		//Create an input object to the underlying sigma DHExtended simulator.
		SigmaDHExtendedCommonInput underlyingInput = new SigmaDHExtendedCommonInput(gArray, hArray);
		return underlyingInput;
	}
	
	/**
	 * Receives three byte arrays and calculates the hash function on their concatenation.
	 * @param u1ToByteArray
	 * @param u2ToByteArray
	 * @param eToByteArray
	 * @return the result of hash(u1ToByteArray+u2ToByteArray+eToByteArray) as BigInteger.
	 */
	protected BigInteger calcW(GroupElement u1, GroupElement u2, GroupElement e) {
		
		byte[] u1ToByteArray = dlog.mapAnyGroupElementToByteArray(u1);
		byte[] u2ToByteArray = dlog.mapAnyGroupElementToByteArray(u2);
		byte[] eToByteArray = dlog.mapAnyGroupElementToByteArray(e);
		
		//Concatenates u1, u2 and e into msgToHash.
		int lengthOfMsgToHash =  u1ToByteArray.length + u2ToByteArray.length + eToByteArray.length;
		byte[] msgToHash = new byte[lengthOfMsgToHash];
		System.arraycopy(u1ToByteArray, 0, msgToHash, 0, u1ToByteArray.length);
		System.arraycopy(u2ToByteArray, 0, msgToHash, u1ToByteArray.length, u2ToByteArray.length);
		System.arraycopy(eToByteArray, 0, msgToHash, u2ToByteArray.length+u1ToByteArray.length, eToByteArray.length);
		
		//Calculates the hash of msgToHash.
		
		//Calls the update function in the Hash interface.
		hash.update(msgToHash, 0, msgToHash.length);

		//Gets the result of hashing the updated input.
		byte[] alpha = new byte[hash.getHashedMsgSize()];
		hash.hashFinal(alpha, 0);
		
		return new BigInteger(alpha);
	}
	

}
