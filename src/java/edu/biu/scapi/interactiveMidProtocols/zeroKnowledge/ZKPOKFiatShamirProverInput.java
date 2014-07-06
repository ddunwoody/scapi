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
package edu.biu.scapi.interactiveMidProtocols.zeroKnowledge;

import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaProverInput;

/**
 * Concrete input for ZKPOK FiatShamir prover.<p>
 * It contains input for the underlying sigma protocol and possible context information.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class ZKPOKFiatShamirProverInput implements ZKProverInput{

	private SigmaProverInput input; //Input for the underlying sigma protocol.
	private byte[] context;			  //possible context information.
	
	/**
	 * This constructor should be used when the user has a context information.
	 * @param input for the underlying sigma protocol.
	 * @param cont context information
	 */
	public ZKPOKFiatShamirProverInput(SigmaProverInput input, byte[] cont){
		this.input = input;
		this.context = cont;
	}
	
	/**
	 * This constructor should be used when the user has no context information.
	 * @param input for the underlying sigma protocol.
	 */
	public ZKPOKFiatShamirProverInput(SigmaProverInput input){
		this.input = input;
		this.context = null;
	}
	
	/**
	 * Returns the input for the underlying Sigma protocol.
	 * @return the input for the underlying Sigma protocol.
	 */
	public SigmaProverInput getSigmaInput(){
		return input;
	}
	
	/**
	 * Returns the context information. If there is no such thing, return null.
	 * @return context information.
	 */
	public byte[] getContext(){
		return context;
	}
}
