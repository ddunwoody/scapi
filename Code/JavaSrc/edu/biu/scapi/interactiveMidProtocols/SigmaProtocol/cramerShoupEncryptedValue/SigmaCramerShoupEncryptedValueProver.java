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
package edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.cramerShoupEncryptedValue;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;

import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.DlogBasedSigma;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.SigmaProverComputation;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.SigmaSimulator;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.dhExtended.SigmaDHExtendedProver;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.dhExtended.SigmaDHExtendedProverInput;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.utility.SigmaProtocolInput;
import edu.biu.scapi.interactiveMidProtocols.SigmaProtocol.utility.SigmaProtocolMsg;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.CramerShoupPublicKey;
import edu.biu.scapi.midLayer.ciphertext.CramerShoupOnGroupElementCiphertext;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.dlog.cryptopp.CryptoPpDlogZpSafePrime;
import edu.biu.scapi.primitives.dlog.miracl.MiraclDlogECF2m;
import edu.biu.scapi.primitives.hash.CryptographicHash;
import edu.biu.scapi.primitives.hash.cryptopp.CryptoPpSHA1;

/**
 * Concrete implementation of Sigma Protocol prover computation. <p>
 * 
 * This protocol is used to prove that the value encrypted under Cramer-Shoup in the ciphertext (u1,u2,e,v) 
 * with public-key g1,g2,c,d,h is x. <p>
 * The protocol is for the case that the prover knows the randomness used to encrypt.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class SigmaCramerShoupEncryptedValueProver implements SigmaProverComputation, DlogBasedSigma{

	/*	
	  This class uses an instance of SigmaDHExtendedProver with:
	  
	  		•	Common DlogGroup
			•	Common input: (g1,g2,g3,g4,h1,h2,h3,h4) = (g1,g2,h,cd^w,u1,u2,e/x,v)
			•	P’s private input: r

	*/	 
	
	private SigmaDHExtendedProver sigmaDH;	//underlying SigmaDHExtendedProver to use.
	private DlogGroup dlog;					//We save the dlog because we need it to calculate the input for the underlying Sigma prover.
	private CryptographicHash hash;			//Underlying hash function that used in the CramerShoup cryptosystem.
	
	/**
	 * Constructor that gets the underlying DlogGroup, CryptographicHash, soundness parameter and SecureRandom.
	 * @param dlog DlogGroup used in CramerShoup encryption scheme.
	 * @param hash CryptographicHash used in CramerShoup encryption scheme. 
	 * @param t Soundness parameter in BITS.
	 * @param random
	 */
	public SigmaCramerShoupEncryptedValueProver(DlogGroup dlog, CryptographicHash hash, int t, SecureRandom random) {
		
		setParameters(dlog, hash, t, random);
	}
	
	/**
	 * Default constructor that chooses default values for the parameters.
	 */
	public SigmaCramerShoupEncryptedValueProver() {
	
		DlogGroup dlogTemp;
		try {
			//Create Miracl Koblitz 233 Elliptic curve.
			dlogTemp = new MiraclDlogECF2m("K-233");
		} catch (IOException e) {
			//If there is a problem with the elliptic curves file, create Zp DlogGroup.
			dlogTemp = new CryptoPpDlogZpSafePrime();
		}
		
		setParameters(dlogTemp, new CryptoPpSHA1(), 80, new SecureRandom());
	}
	
	/**
	 * Sets the given parameters.
	 * @param dlog DlogGroup used in CramerShoup encryption scheme.
	 * @param hash CryptographicHash used in CramerShoup encryption scheme.
	 * @param t Soundness parameter in BITS.
	 * @param random
	 */
	private void setParameters(DlogGroup dlog, CryptographicHash hash, int t, SecureRandom random) {
		//Creates the underlying SigmaDHProver object with the given parameters.
		sigmaDH = new SigmaDHExtendedProver(dlog, t, random);
		this.dlog = dlog;
		this.hash = hash;
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
	 * Sets the input for this Sigma protocol.
	 * @param input MUST be an instance of SigmaCramerShoupEncryptedValueProverInput.
	 * @throws IllegalArgumentException if input is not the expected.
	 */
	public void setInput(SigmaProtocolInput in) {
		if (!(in instanceof SigmaCramerShoupEncryptedValueProverInput)){
			throw new IllegalArgumentException("the given input must be an instance of SigmaCramerShoupEncryptedValueProverInput");
		}
		
		//Gets the input values.
		SigmaCramerShoupEncryptedValueProverInput input = (SigmaCramerShoupEncryptedValueProverInput) in;
		CramerShoupPublicKey publicKey = input.getPublicKey();
		CramerShoupOnGroupElementCiphertext cipher = input.getCipher();
		GroupElement x = input.getX();
		BigInteger r = input.getR();
		
		//Prepare the input for the underlying SigmaDHExtendedProver.
		ArrayList<GroupElement> gArray = new ArrayList<GroupElement>();
		ArrayList<GroupElement> hArray = new ArrayList<GroupElement>();
		
		//Converts the given input to the necessary input to the underlying SigmaDHExtendedProver.
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
		
		//Create an input object to the underlying sigma DHExtended prover.
		SigmaDHExtendedProverInput underlyingInput = new SigmaDHExtendedProverInput(gArray, hArray, r);
		sigmaDH.setInput(underlyingInput);
		
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

	/**
	 * Samples random value r in Zq.
	 */
	public void sampleRandomValues() {
		//Delegates to the underlying Sigma DHExtended prover.
		sigmaDH.sampleRandomValues();
	}

	/**
	 * Computes the first message of the protocol.
	 * @return the computed message
	 */
	public SigmaProtocolMsg computeFirstMsg() {
		//Delegates the computation to the underlying Sigma DHExtended prover.
		return sigmaDH.computeFirstMsg();
	}

	/**
	 * Computes the second message of the protocol.
	 * @param challenge
	 * @return the computed message.
	 * @throws CheatAttemptException if the received challenge's length is not equal to the soundness parameter.
	 */
	public SigmaProtocolMsg computeSecondMsg(byte[] challenge) throws CheatAttemptException {
		//Delegates the computation to the underlying Sigma DHExtended prover.
		return sigmaDH.computeSecondMsg(challenge);
		
	}
	
	/**
	 * Returns the simulator that matches this sigma protocol prover.
	 * @return SigmaCramerShoupEncryptedValueSimulator.
	 */
	public SigmaSimulator getSimulator(){
		return new SigmaCramerShoupEncryptedValueSimulator(sigmaDH.getSimulator());
	}

}
