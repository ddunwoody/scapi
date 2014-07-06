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
import edu.biu.scapi.interactiveMidProtocols.ot.OTOnByteArrayROutput;
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.OTBatchRInput;
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.OTBatchROutput;
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.OTBatchReceiver;
import edu.biu.scapi.securityLevel.SemiHonest;

/**
 * A concrete class for Semi-Honest OT extension receiver. <P>
 * 
 * The Semi-Honest OT extension implemented is a SCAPI wrapper of the native implementation by Michael Zohner from the paper: <p>
 * "G. Asharov, Y. Lindell, T. Schneier and M. Zohner. More Efficient Oblivious Transfer and Extensions for Faster Secure Computation. ACM CCS 2013." <p>
 * See http://eprint.iacr.org/2013/552.pdf for more information.
 * 
 * The base OT is done once in the construction time. After that, the transfer function will be always optimized and fast, no matter how much OT's there are.<p>
 * 
 * There are three versions of OT extension: General, Correlated and Random. The difference between them is the way of getting the inputs: <p>
 * In general OT extension both x0 and x1 are given by the user.<p>
 * In Correlated OT extension the user gives a delta array and x0, x1 arrays are chosen such that x0 = delta^x1.<p>
 * In random OT extension both x0 and x1 are chosen randomly.<p>
 * To allow the user decide which OT extension's version he wants, each option has a corresponding input class. <p>
 * The particular OT extension version is executed according to the given input instance; 
 * For example, if the user gave as input an instance of OTExtensionRandomRInput than the random OT Extension will be execute.<p>
 * 
 * NOTE: Unlike a regular implementation, the connection is done via the native code and thus the channel provided in the transfer function is ignored.  
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 *
 */
public class OTSemiHonestExtensionReceiver implements SemiHonest, OTBatchReceiver{
	
	
	private long receiverPtr; //Pointer that holds the receiver pointer in the c++ code.
	
	// This function initializes the receiver. It creates sockets to communicate with the sender and attaches these sockets to the receiver object.
	// It outputs the receiver object with communication abilities built in. 
	private native long initOtReceiver(String ipAddress, int port, int koblitzOrZpSize, int numOfThreads);
	/*
	 * The native code that runs the OT extension as the receiver.
	 * @param receiverPtr The pointer initialized via the function initOtReceiver
	 * @param sigma An array holding the input of the receiver, that is, the 0 and 1 choices for each OT.
	 * @param numOfOts The number or OTs that the protocol runs.
	 * @param bitLength The length of each item in the OT. The size of each x0, x1 which must be the same for all x0, x1.
	 * @param output The output of all the OTs. This is provided as a one dimensional array that gets all the data serially one after the other. The 
	 * 				 array is given empty and the native code fills it with the result of the multiple OT results.
	 * @param version The particular OT type to run.
	 */
	private native void runOtAsReceiver(long receiverPtr, byte[] sigma, int numOfOts, int bitLength, byte[] output, String version);
	//Deletes the native object.
	private native void deleteReceiver(long receiverPtr);
	
	/**
	 * A constructor that creates the native receiver with communication abilities. <p>
	 * It uses the ip address and port given in the party object.<p>
	 * The construction runs the base OT phase. Further calls to transfer function will be optimized and fast, no matter how much OTs there are.
	 * @param party An object that holds the ip address and port.
	 * @param koblitzOrZpSize An integer that determines whether the OT extension uses Zp or ECC koblitz. The optional parameters are the following.
	 * 		  163,233,283 for ECC koblitz and 1024, 2048, 3072 for Zp.
	 * @param numOfThreads
	 * 	      
	 */
	public OTSemiHonestExtensionReceiver(Party party, int koblitzOrZpSize, int numOfThreads ){
		// Create the receiver by passing the local host address.
		receiverPtr = initOtReceiver(party.getIpAddress().getHostAddress(), party.getPort(), koblitzOrZpSize, numOfThreads);
		
	}
	
	
	/**
	 * Default constructor. Initializes the receiver by passing the ip address and uses koblitz 163 as a default dlog group. <P>
	 * The construction runs the base OT phase. Further calls to transfer function will be optimized and fast, no matter how much OTs there are.
	 * @param party An object that holds the ip address and port.
	 */
	public OTSemiHonestExtensionReceiver(Party party ){
		
		// Create the receiver by passing the local host address.
		receiverPtr = initOtReceiver(party.getIpAddress().getHostAddress(), party.getPort(), 163, 1);
	}
	

	/**
	 * The overloaded function that runs the protocol.<p>
	 * After the base OT was done by the constructor, call to this function will be optimized and fast, no matter how much OTs there are.
	 * @param channel Disregarded. This is ignored since the connection is done in the c++ code.
	 * @param input The input for the receiver specifying the version of the OT extension to run. 
	 * Every call to the transfer function can run a different OT extension version.
	 */
	public OTBatchROutput transfer(Channel channel, OTBatchRInput input) {
		
		//We set the version to be the general case, if a different call was made we will change it later to the relevant version.
		String version = "general";
		
		//Check if the input is valid. If input is not instance of OTRExtensionInput, throw Exception.
		if (!(input instanceof OTExtensionRInput)){
			throw new IllegalArgumentException("input should be an instance of OTRExtensionInput.");
		}
		
		//If the user gave correlated input, change the version of the OT to correlated.
		if(input instanceof OTExtensionCorrelatedRInput){
			version = "correlated";
		}
		
		//If the user gave random input, change the version of the OT to random.
		if(input instanceof OTExtensionRandomRInput){
			version = "random";
		}
		
		byte[] sigmaArr = ((OTExtensionRInput) input).getSigmaArr();
		int numOfOts = sigmaArr.length;
		int elementSize = ((OTExtensionRInput) input).getElementSize();
		
		byte[] outputBytes = new byte[numOfOts*elementSize/8];
		
		//Run the protocol using the native code in the dll.
		runOtAsReceiver(receiverPtr, sigmaArr, numOfOts, elementSize, outputBytes, version);
		
		return new OTOnByteArrayROutput(outputBytes);
	}
	
	
	/**
	 * Deletes the native OT object.
	 */
	public void finalize() throws Throwable {
		//Delete from the dll the dynamic allocation of the receiver.
		deleteReceiver(receiverPtr);
	}
	
	static { 
		 //Loads the OT extension jni dll.
		 System.loadLibrary("OtExtensionJavaInterface");
	 }
	
	

}
