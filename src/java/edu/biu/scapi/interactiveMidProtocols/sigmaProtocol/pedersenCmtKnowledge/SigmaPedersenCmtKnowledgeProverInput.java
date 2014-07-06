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

import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaProverInput;
import edu.biu.scapi.primitives.dlog.GroupElement;

/**
 * Concrete implementation of SigmaProtocol input, used by the SigmaPedersenCTKnowledgeProver.<p>
 * 
 * In SigmaPedersenCTKnowledge protocol, the prover gets a GroupElement h, commitment message and 
 * values x,r <- Zq such that c = g^r * h^x.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class SigmaPedersenCmtKnowledgeProverInput implements SigmaProverInput{
	
	private SigmaPedersenCmtKnowledgeCommonInput params;
	private BigInteger x;
	private BigInteger r;
	
	/**
	 * Sets the given h (public key), commitment value, committed value and the random value used to commit.
	 * @param h public key used to commit.
	 * @param commitment the actual commitment value.
	 * @param x committed value
	 * @param r random value used to commit
	 */
	public SigmaPedersenCmtKnowledgeProverInput(GroupElement h, GroupElement commitment, BigInteger x, BigInteger r){
		params = new SigmaPedersenCmtKnowledgeCommonInput(h, commitment);
		this.x = x;
		this.r = r;
	}
	
	/**
	 * Returns the committed value.
	 * @return the committed value.
	 */
	public BigInteger getX(){
		return x;
	}

	/**
	 * Returns the random value used to commit.
	 * @return random value used to commit.
	 */
	public BigInteger getR(){
		return r;
	}

	@Override
	public SigmaPedersenCmtKnowledgeCommonInput getCommonParams() {
		return params;
	}

	 
	
}
