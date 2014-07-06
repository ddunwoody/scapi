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
package edu.biu.scapi.interactiveMidProtocols.commitmentScheme.pedersen;

import java.io.Serializable;
import java.math.BigInteger;

import edu.biu.scapi.interactiveMidProtocols.BigIntegerRandomValue;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCDecommitmentMessage;

/**
 * Concrete implementation of decommitment message used by Pedersen commitment scheme.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class CmtPedersenDecommitmentMessage implements CmtCDecommitmentMessage, Serializable {

	
	private static final long serialVersionUID = 510887524381013384L;
	
	private BigInteger x; 				//Committer's private input x in Zq
	private BigIntegerRandomValue r; 	//Random value sampled during the sampleRandomValues stage;
	
	/**
	 * Constructor that sets the given committed value and random value.
	 * @param x the committed value
	 * @param r the random value used for commit.
	 */
	public CmtPedersenDecommitmentMessage(BigInteger x, BigIntegerRandomValue r) {
		super();
		this.x = x;
		this.r = r;
	}
	
	/**
	 * Returns the committed value.
	 */
	public BigInteger getX() {
		return x;
	}

	/**
	 * Returns the random value used for commit.
	 */
	public BigIntegerRandomValue getR() {
		return r;
	}
	
}
