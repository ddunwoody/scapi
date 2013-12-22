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

import java.io.IOException;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.comm.Party;
import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.exceptions.InvalidDlogGroupException;
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.OTBatchSInput;
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.OTBatchSOutput;
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.OTBatchSender;
import edu.biu.scapi.securityLevel.SemiHonest;

/**
 * Concrete class for Semi-Honest OT extension sender.
 * 
 * This class is a wrapper to the sender side of the ot extension code written in c++. The c++ code is called via a dll that uses jni to pass data between 
 * the java and native code.
 * 
 * NOTE: Unlike a regular implementation the connection is done via the native code and thus the channel provided in the transfer function is ignored.  
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 *
 */
public class OTSemiHonestExtensionSender  implements SemiHonest, OTBatchSender{
	
	private long senderPtr;//pointer that holds the sender pointer in the c++ code.
	
	//This function initializes the receiver. It creates sockets to communicate with the sender and attaches these sockets to the receiver object.
	//It outputs the receiver object with communication abilities built in. 
	private native long initOtSender(String ipAddress, int port, int koblitzOrZpSize);
	
	//run the OT as the sender. The inputs are x0 and x1 vectors.
	
	/**
	 * The native code that runs the ot extension as the sender.
	 * @param senderPtr The pointer initialized via the function initOtSender
	 * @param x0 an array that holds all the x0 values for each of the ot's serially.
	 * @param x1 an array that holds all the x1 values for each of the ot's serially.
	 * @param numOfOts The number or ot's that the protocol runs
	 * @param bitLength The length of each item in the ot. The size of each x0,x1 which must be the same for all x0,x1.
	 */
	private native void runOtAsSender(long senderPtr, byte[] x0, byte[]x1, byte[] delta, int numOfOts, int bitLength, String version);
	
	
	/**
	 * 
	 * 
	 * @param party An object that holds the ip address and port
	 * @param koblitzOrZpSize An integer that determines whether the ot extension uses Zp or ECC koblitz. The optional parameters are the following.
	 * 		  163,233,283 for ECC koblitz and 1024, 2048, 3072 for Zp
	 * 	      
	 */
	public OTSemiHonestExtensionSender(Party party, int koblitzOrZpSize ){
		
		
		//create the sender by passing the local host address.
		//receiverPtr = initOtSender("127.0.0.1", 7766);
		
		senderPtr = initOtSender(party.getIpAddress().getHostAddress(), party.getPort(), koblitzOrZpSize);
		

	}
	
	
	/**
	 * Initializes the receiver by passing the ip address and uses koblitz 163 as default dlog group. 
	 * 
	 * @param party An object that holds the ip address and port
	 * 	      
	 */
	public OTSemiHonestExtensionSender(Party party ){
		
		
		//create the sender by passing the local host address.
		//receiverPtr = initOtSender("127.0.0.1", 7766);
		
		senderPtr = initOtSender(party.getIpAddress().getHostAddress(), party.getPort(), 163);
		

	}

	/**
	 * The overloaded function that runs the protocol.
	 * @param channel Disregarded. This is ignored since the connection is done in the c++ code
	 * @param input The input for the sender 
	 */
	public OTBatchSOutput transfer(Channel channel, OTBatchSInput input) throws IOException,
			ClassNotFoundException, CheatAttemptException,
			InvalidDlogGroupException {
		
		int numOfOts;

		//check if the input is valid.
		//If input is not instance of OTSExtensionInput, throw Exception.
		if (input instanceof OTExtensionGeneralSInput){
			
			//Retrieve the values from the input object
			byte[] x0 = ((OTExtensionGeneralSInput) input).getX0Arr();
			byte[] x1 = ((OTExtensionGeneralSInput) input).getX1Arr();
			numOfOts = ((OTExtensionGeneralSInput) input).getNumOfOts();
			
			//call the native function
			runOtAsSender(senderPtr, x0,x1, null, numOfOts, x0.length/numOfOts*8, "general");
		
			
			return null;
		}
		
		else if(input instanceof OTExtensionCorrelatedSInput){
			 
			
			byte[] delta = ((OTExtensionCorrelatedSInput) input).getDelta();
			

			//prepare empty x0 and x1 for the output
			byte[] x0 = new byte[delta.length];
			byte[] x1 = new byte[delta.length];
			
			numOfOts = ((OTExtensionCorrelatedSInput) input).getNumOfOts();
			
			//call the native function. It will fill x0 and x1
			runOtAsSender(senderPtr, x0, x1, delta, numOfOts, delta.length/numOfOts*8, "correlated");
			
			return new OTExtensionSOutput(x0,x1);
		
		}
		
		else if(input instanceof OTExtensionRandomSInput){
			 
			numOfOts = ((OTExtensionRandomSInput) input).getNumOfOts();
			
			int bitLength = ((OTExtensionRandomSInput) input).getBitLength();
			
			//prepare empty x0 and x1 for the output
			byte[] x0 = new byte[numOfOts * bitLength/8];
			byte[] x1 = new byte[numOfOts * bitLength/8];
			
			
			//call the native function. It will fill x0 and x1
			runOtAsSender(senderPtr, x0, x1, null, numOfOts, bitLength, "random");
			
			return new OTExtensionSOutput(x0,x1);
		}
		return null;
		
		
		
	}

 static {
		 
		 //loads the OtExtensionJavaInterface jni dll
		 System.loadLibrary("OtExtensionJavaInterface");
	 }
	

}
