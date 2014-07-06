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

import java.io.IOException;
import java.io.ObjectOutputStream;
import java.util.ArrayList;

import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaCommonInput;
import edu.biu.scapi.primitives.dlog.GroupElement;

/**
 * Concrete implementation of SigmaProtocol input, used by the SigmaDHExtended verifier and simulator.<p>
 * In SigmaProtocolDHExtended, the common input contains an extended DH tuple - (g1,…,gm,h1,…,hm).
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class SigmaDHExtendedCommonInput implements SigmaCommonInput{

	private static final long serialVersionUID = 2595300376835152550L;
	private ArrayList<GroupElement> gArray;
	private ArrayList<GroupElement> hArray;
	
	/**
	 * Sets the input arrays.
	 * @param gArray
	 * @param hArray
	 */
	public SigmaDHExtendedCommonInput(ArrayList<GroupElement> gArray, ArrayList<GroupElement> hArray){
		this.gArray = gArray;
		this.hArray = hArray;
	}
	
	public ArrayList<GroupElement> getGArray(){
		return gArray;
	}
	
	public ArrayList<GroupElement> getHArray(){
		return hArray;
	}
	
	private void writeObject(ObjectOutputStream out) throws IOException {  
        int gSize = gArray.size();
		for(int i=0; i<gSize; i++){
			out.writeObject(gArray.get(i).generateSendableData());
		}
		
		int hSize = hArray.size();
		for(int i=0; i<hSize; i++){
			out.writeObject(hArray.get(i).generateSendableData());
		}
    }  
}
