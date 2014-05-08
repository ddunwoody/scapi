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
 * In the correlated OT extension scenario the sender inputs a delta array and gets as an input x0, x1 such that x0 = x1^delta. 
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 *
 */
public class OTExtensionCorrelatedSInput implements OTBatchSInput{

	private byte[] delta;	// An array that holds all the delta for all the senders, serially. 
							// This is a one dimensional array where the values are stored one after the other rather than a two dimensional array. 
							// The size of each element can be calculated by delta.length/numOfOts.
	
	private int numOfOts;	//number of ot's in the OT extension.
	
	/**
	 * Constructor that sets the delta and the number of OTs.
	 * @param delta 
	 * @param numOfOts The number of OT's in the OT extension.
	 */
	public OTExtensionCorrelatedSInput(byte[] delta, int numOfOts){
		this.delta = delta;
		this.numOfOts = numOfOts;
	}
	
	/**
	 * @return the delta.
	 */
	public byte[] getDelta(){
		return delta;
	}
	
	/**
	 * @return the number of elements in the OT.
	 */
	public int getNumOfOts(){
		return numOfOts;
	}
}
