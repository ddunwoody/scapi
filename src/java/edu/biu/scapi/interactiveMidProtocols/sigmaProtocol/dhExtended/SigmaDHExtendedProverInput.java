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
import java.util.ArrayList;

import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaProverInput;
import edu.biu.scapi.primitives.dlog.GroupElement;

/**
 * Concrete implementation of SigmaProtocol input, used by the SigmaDHExtendedProver.<p>
 * In SigmaProtocolDHExtended, the prover gets an extended DH tuple - (g1,…,gm,h1,…,hm) and a value w in Zq such that hi=gi^w for all i.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class SigmaDHExtendedProverInput implements SigmaProverInput{

	private SigmaDHExtendedCommonInput params;
	private BigInteger w;
	
	/**
	 * Sets the input for the prover. <p>
	 * The prover gets an extended DH tuple - (g1,…,gm,h1,…,hm) and a value w in Zq such that hi=gi^w for all i.
	 * @param gArray
	 * @param hArray
	 * @param w
	 */
	public SigmaDHExtendedProverInput(ArrayList<GroupElement> gArray, ArrayList<GroupElement> hArray, BigInteger w){
		params = new SigmaDHExtendedCommonInput(gArray, hArray);
		this.w = w;
	}
	
	public BigInteger getW(){
		return w;
	}
	
	@Override
	public SigmaDHExtendedCommonInput getCommonParams() {
		
		return params;
	}  
}
