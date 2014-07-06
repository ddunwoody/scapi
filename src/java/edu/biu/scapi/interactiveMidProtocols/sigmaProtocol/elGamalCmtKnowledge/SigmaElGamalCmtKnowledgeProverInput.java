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
package edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.elGamalCmtKnowledge;

import java.math.BigInteger;

import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaProverInput;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.ElGamalPublicKey;


/**
 * Concrete implementation of SigmaProtocol input, used by the SigmaElGamalCTKnowldgeProver.<p>
 * In SigmaElGamalCTKnowldge protocol, the prover gets an ElGamal commitment message and a value w in Zq such that h = g^w.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class SigmaElGamalCmtKnowledgeProverInput implements SigmaProverInput{
	
	private SigmaElGamalCmtKnowledgeCommonInput params;
	private BigInteger w;
	
	/**
	 * Sets the public keyused to ensrypt and the private key.
	 * @param publicKey
	 * @param w
	 */
	public SigmaElGamalCmtKnowledgeProverInput(ElGamalPublicKey publicKey, BigInteger w){
		params = new SigmaElGamalCmtKnowledgeCommonInput(publicKey);
		this.w = w;
	}
	
	/**
	 * Returns the private key.
	 * @return the private key.
	 */
	public BigInteger getW(){
		return w;
	}

	@Override
	public SigmaElGamalCmtKnowledgeCommonInput getCommonParams() {
		return params;
	}
}
