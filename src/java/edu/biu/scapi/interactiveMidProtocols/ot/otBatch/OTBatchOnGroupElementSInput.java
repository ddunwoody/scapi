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
package edu.biu.scapi.interactiveMidProtocols.ot.otBatch;

import java.util.ArrayList;

import edu.biu.scapi.primitives.dlog.GroupElement;

/**
 * Concrete implementation of batch OT sender (on GroupElement) input.<p>
 * In the GroupElement scenario, the sender gets for each i=1,...,m, two DlogGroup elements x0, x1.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class OTBatchOnGroupElementSInput implements OTBatchSInput{
	private ArrayList<GroupElement> x0Arr;
	private ArrayList<GroupElement> x1Arr;
	
	/**
	 * Sets the input for the Batch OT, in case the OT is working on byte[].
	 * @param x0Arr
	 * @param x1Arr
	 */
	public OTBatchOnGroupElementSInput(ArrayList<GroupElement> x0Arr, ArrayList<GroupElement> x1Arr){
		this.x0Arr = x0Arr;
		this.x1Arr = x1Arr;
	}
	
	/**
	 * Returns x0 array, contains all xi0 values of the tuples (xi0, xi1).
	 * @return x0 array.
	 */
	public ArrayList<GroupElement> getX0Arr(){
		return x0Arr;
	}
	
	/**
	 * Returns x1 array, contains all xi1 values of the tuples (xi0, xi1).
	 * @return x1 array.
	 */
	public ArrayList<GroupElement> getX1Arr(){
		return x1Arr;
	}
}
