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

import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.OTBatchRInput;


/**
 * An abstract OT receiver input.<P>
 * 
 * All the concrete classes are the same and differ only in the name.
 * The reason a class is created for each version is due to the fact that a respective class is created for the sender and we wish to be consistent. 
 * The name of the class determines the version of the OT extension we wish to run.
 * 
 * In all OT extension scenarios the receiver gets i bits. Each byte holds a bit for each OT in the OT extension protocol.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 *
 */
abstract public class OTExtensionRInput implements OTBatchRInput{
	private byte[] sigmaArr; 		// Each byte holds a sigma bit for each OT in the OT extension protocol.
	private int elementSize;	// The size of each element in the ot extension. All elements must be of the same size.
	
	/**
	 * Constructor that sets the sigma array and the number of OT elements.
	 * @param sigmaArr An array of sigma for each OT.
	 * @param elementSize The size of each element in the OT extension, in bits. 
	 */
	public OTExtensionRInput(byte[] sigmaArr, int elementSize){
		this.sigmaArr = sigmaArr;
		this.elementSize = elementSize;
	}
	
	/**
	 * @return byte[] the sigma array.
	 */
	public byte[] getSigmaArr(){
		return sigmaArr;
	}

	/**
	 * 
	 * @return the number of OT elements.
	 */
	public int getElementSize() {
		return elementSize;
	}

}
