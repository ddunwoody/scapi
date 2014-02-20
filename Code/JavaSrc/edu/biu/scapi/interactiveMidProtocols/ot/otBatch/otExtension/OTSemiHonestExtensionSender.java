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

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.comm.Party;
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.OTBatchSInput;
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.OTBatchSOutput;
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.OTBatchSender;
import edu.biu.scapi.securityLevel.SemiHonest;

/**
 * Concrete class for Semi-Honest OT extension sender. <P>
 * 
 * This class is a wrapper to the sender side of the OT extension code written in c++. The c++ code is called via a dll that uses jni to pass data between 
 * the java and native code. <P>
 * 
 * NOTE: Unlike a regular implementation the connection is done via the native code and thus the channel provided in the transfer function is ignored.  
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 *
 */
public class OTSemiHonestExtensionSender  implements SemiHonest, OTBatchSender{
	
	private long senderPtr; //Pointer that holds the sender pointer in the c++ code.
	
	// This function initializes the receiver. It creates sockets to communicate with the sender and attaches these sockets to the receiver object.
	// It outputs the receiver object with communication abilities built in. 
	private native long initOtSender(String ipAddress, int port, int koblitzOrZpSize, int numOfThreads);
	
	/**
	 * The native code that runs the ot extension as the sender.
	 * @param senderPtr The pointer initialized via the function initOtSender
	 * @param x0 an array that holds all the x0 values for each of the ot's serially.
	 * @param x1 an array that holds all the x1 values for each of the ot's serially.
	 * @param delta 
	 * @param numOfOts The number or OTs that the protocol runs.
	 * @param bitLength The length of each item in the OT. The size of each x0, x1 which must be the same for all x0, x1.
	 * @param version the OT extension version the user want to use.
	 */
	private native void runOtAsSender(long senderPtr, byte[] x0, byte[]x1, byte[] delta, int numOfOts, int bitLength, String version);
	
	
	/**
	 * Constructor that create the native sender with communication abilities. It uses the ip address and port given in the party object.
	 * @param party An object that holds the ip address and port
	 * @param koblitzOrZpSize An integer that determines whether the ot extension uses Zp or ECC koblitz. The optional parameters are the following.
	 * 		  163,233,283 for ECC koblitz and 1024, 2048, 3072 for Zp
	 * @param numOfThreads    
	 */
	public OTSemiHonestExtensionSender(Party party, int koblitzOrZpSize, int numOfThreads ){
		
		
		// Create the sender by passing the local host address.
		//receiverPtr = initOtSender("127.0.0.1", 7766);
		senderPtr = initOtSender(party.getIpAddress().getHostAddress(), party.getPort(), koblitzOrZpSize, numOfThreads);
	}
	
	
	/**
	 * Default constructor. Initializes the sender by passing the ip address and uses koblitz 163 as default dlog group. 
	 * @param party An object that holds the ip address and port.
	 */
	public OTSemiHonestExtensionSender(Party party ){
		
		
		// Create the sender by passing the local host address.
		senderPtr = initOtSender(party.getIpAddress().getHostAddress(), party.getPort(), 163, 1);
	}

	/**
	 * The overloaded function that runs the protocol.
	 * @param channel Disregarded. This is ignored since the connection is done in the c++ code.
	 * @param input The input for the sender specifying the version of the OT extension to run. 
	 * Every call to the transfer function can run a different OT extension version.
	 */
	public OTBatchSOutput transfer(Channel channel, OTBatchSInput input) {
		
		int numOfOts;

		// In case the given input is general input.
		if (input instanceof OTExtensionGeneralSInput){
			
			//Retrieve the values from the input object.
			byte[] x0 = ((OTExtensionGeneralSInput) input).getX0Arr();
			byte[] x1 = ((OTExtensionGeneralSInput) input).getX1Arr();
			numOfOts = ((OTExtensionGeneralSInput) input).getNumOfOts();
			
			//call the native function
			runOtAsSender(senderPtr, x0,x1, null, numOfOts, x0.length/numOfOts*8, "general");
		
			//This version has no output. Return null.
			return null;
		//In case the given input is correlated input.
		} else if(input instanceof OTExtensionCorrelatedSInput){
			 
			byte[] delta = ((OTExtensionCorrelatedSInput) input).getDelta();
			
			// Prepare empty x0 and x1 for the output.
			byte[] x0 = new byte[delta.length];
			byte[] x1 = new byte[delta.length];
			
			numOfOts = ((OTExtensionCorrelatedSInput) input).getNumOfOts();
			
			// Call the native function. It will fill x0 and x1.
			runOtAsSender(senderPtr, x0, x1, delta, numOfOts, delta.length/numOfOts*8, "correlated");
			
			//Return output contains x0, x1.
			return new OTExtensionSOutput(x0,x1);
		
		//In case the given input is random input.
		} else if(input instanceof OTExtensionRandomSInput){
			 
			numOfOts = ((OTExtensionRandomSInput) input).getNumOfOts();
			int bitLength = ((OTExtensionRandomSInput) input).getBitLength();
			
			// Prepare empty x0 and x1 for the output.
			byte[] x0 = new byte[numOfOts * bitLength/8];
			byte[] x1 = new byte[numOfOts * bitLength/8];
			
			// Call the native function. It will fill x0 and x1.
			runOtAsSender(senderPtr, x0, x1, null, numOfOts, bitLength, "random");
			
			//Return output contains x0, x1.
			return new OTExtensionSOutput(x0,x1);
		
		//If input is not instance of the above inputs, throw Exception.
		} else {
			throw new IllegalArgumentException("input should be an instance of OTExtensionGeneralSInput or OTExtensionCorrelatedSInput or OTExtensionRandomSInput.");
		}
		
	}

	static {
		 
		 // Loads the OtExtensionJavaInterface jni dll.
		 System.loadLibrary("OtExtensionJavaInterface");
	 }
	

}
