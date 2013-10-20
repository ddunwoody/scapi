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
package edu.biu.scapi.interactiveMidProtocols.ot.otExtensionSemiHonest;

import java.io.IOException;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.interactiveMidProtocols.ot.OTRExtensionInput;
import edu.biu.scapi.interactiveMidProtocols.ot.OTRInput;
import edu.biu.scapi.interactiveMidProtocols.ot.OTROnByteArrayOutput;
import edu.biu.scapi.interactiveMidProtocols.ot.OTROutput;
import edu.biu.scapi.interactiveMidProtocols.ot.OTReceiver;
import edu.biu.scapi.securityLevel.SemiHonest;

/**
 * Concrete class for Semi-Honest OT extension receiver.
 * 
 * This class is a wrapper to the receiver side of the ot extension code written in c++. The c++ code is called via a dll that uses jni to pass data between 
 * the java and native code.
 * 
 * NOTE: Unlike a regular implementation the connection is done via the native code and thus the channel provided in the transfer function is ignored.  
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University Meital Levy)
 *
 */
public class OTSemiHonestExtensionReceiver implements SemiHonest, OTReceiver{
	
	
	private long receiverPtr;//pointer that holds the receiver pointer in the c++ code.

	//This function initializes the receiver. It creates sockets to communicate with the sender and attaches these sockets to the receiver object.
	//It outputs the receiver object with communication abilities built in. 
	private native long initOtReceiver(String ipAddress, int port);
	
	
	/**
	 *
	 * The native code that runs the ot extension as the receiver.
	 * @param receiverPtr The pointer initialized via the function initOtReceiver
	 * @param sigma An array holding the input of the receiver, that is, the 0 and 1 choices for each ot.
	 * @param numOfOts The number or ot's that the protocol runs
	 * @param bitLength The length of each item in the ot. The size of each x0,x1 which must be the same for all x0,x1.
	 * @param output the output of all the ot's. This is provided as a one dimensional array that gets all the data serially one after the other. The 
	 * 				 array is given empty and the native code filles it with the result of the multiple ot results.
	 */
	private native void runOtAsReceiver(long receiverPtr, byte[] sigma, int numOfOts, int bitLength, byte[] output);
	
	public OTSemiHonestExtensionReceiver(){
		
		//create the receiver by passing the local host address.
		receiverPtr = initOtReceiver("127.0.0.1", 7766);

	}

	/**
	 * The overloaded function that runs the protocol.
	 * @param channel Disregarded. This is ignored since the connection is done in the c++ code
	 * @param input The input for the receiver 
	 */
	
	public OTROutput transfer(Channel channel, OTRInput input)
			throws CheatAttemptException, IOException, ClassNotFoundException {
		
		
		int elementSize = 16;
		
		//check if the input is valid.
		//If input is not instance of OTRBasicInput, throw Exception.
		if (!(input instanceof OTRExtensionInput)){
			throw new IllegalArgumentException("input should be an instance of OTRExtensionInput.");
		}
		
		byte[] sigmaArr = ((OTRExtensionInput) input).getSigmaArr();
		int numOfOts = sigmaArr.length;
		
		
		byte[] outputBytes = new byte[numOfOts*elementSize/8];
		
		runOtAsReceiver(receiverPtr, sigmaArr, numOfOts, elementSize, outputBytes);
		
		
		return new OTROnByteArrayOutput(outputBytes);
	}
	
 static {
		 
		 //loads the ot extension jni dll
		 System.loadLibrary("OtExtensionJavaInterface");
	 }
	
	

}
