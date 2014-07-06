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
package edu.biu.scapi.interactiveMidProtocols.ot.otBatch.otExtension;

import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.OTBatchSInput;

/**
 * A concrete class for OT extension input for the sender. <p>
 * In the random OT extension scenario the sender does not send x0 and x1, rather it gets them as an output.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 *
 */
public class OTExtensionRandomSInput implements OTBatchSInput{

	private int bitLength;// Since there is no input we need to send the size of each OT so that the OT extension can generate x0 and x1 with the right size.
	
	private int numOfOts; // Number of OTs in the OT extension.
	
	/**
	 * Constructor that sets the number of OTs and the size of each OT.
	 * @param numOfOts number of OTs in the OT extension.
	 * @param bitLength The size of each element in the OT extension, in bits. 
	 */
	public OTExtensionRandomSInput(int numOfOts, int bitLength){

		this.numOfOts = numOfOts;
		this.bitLength = bitLength;
	}
	
	/**
	 * @return the number of OT elements.
	 */
	public int getNumOfOts(){
		return numOfOts;
	}
	
	/**
	 * @return the size of each OT.
	 */
	public int getBitLength(){
		
		return bitLength;
	}
}
