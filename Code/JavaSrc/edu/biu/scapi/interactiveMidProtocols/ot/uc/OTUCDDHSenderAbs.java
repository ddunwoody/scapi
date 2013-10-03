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
package edu.biu.scapi.interactiveMidProtocols.ot.uc;

import java.io.IOException;
import java.io.Serializable;
import java.security.SecureRandom;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.SecurityLevelException;
import edu.biu.scapi.interactiveMidProtocols.ot.OTRMsg;
import edu.biu.scapi.interactiveMidProtocols.ot.OTSInput;
import edu.biu.scapi.interactiveMidProtocols.ot.OTSMsg;
import edu.biu.scapi.interactiveMidProtocols.ot.OTSender;
import edu.biu.scapi.interactiveMidProtocols.ot.OTUtil;
import edu.biu.scapi.interactiveMidProtocols.ot.OTUtil.RandOutput;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.securityLevel.DDH;
import edu.biu.scapi.securityLevel.UC;

/**
 * Abstract class for oblivious transfer sender based on the DDH assumption that achieves UC security in
 * the common reference string model.
 * This OT has two modes: one is on ByteArray and the second is on GroupElement.
 * The difference is in the input and output types and the way to process them. 
 * In spite that, there is a common behavior for both modes which this class implements.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
abstract class OTUCDDHSenderAbs implements OTSender, UC{

	/*	
	  This class runs the following protocol:
		 	WAIT for message (g,h) from R
			COMPUTE (u0,v0) = RAND(g0,g,h0,h)
			COMPUTE (u1,v1) = RAND(g1,g,h1,h)
			COMPUTE c0 = x0 XOR KDF(|x0|,v0)
			COMPUTE c1 = x1 XOR KDF(|x1|,v1)
			SEND (u0,c0) and (u1,c1) to R
			OUTPUT nothing
	 */	 

	protected DlogGroup dlog;
	private SecureRandom random;
	private GroupElement g0, g1, h0, h1; //Common reference string
	
	/**
	 * Constructor that sets the given common reference string composed of a DLOG 
	 * description (G,q,g0) and (g0,g1,h0,h1) which is a randomly chosen non-DDH tuple and random.
	 * @param dlog must be DDH secure.
	 * @param g0 
	 * @param g1 
	 * @param h0 
	 * @param h1 
	 * @param random
	 * @throws SecurityLevelException if the given dlog is not DDH secure
	 */
	OTUCDDHSenderAbs(DlogGroup dlog, GroupElement g0, GroupElement g1, 
			GroupElement h0, GroupElement h1, SecureRandom random) throws SecurityLevelException{
		//The underlying dlog group must be DDH secure.
		if (!(dlog instanceof DDH)){
			throw new SecurityLevelException("DlogGroup should have DDH security level");
		}
		
		this.dlog = dlog;
		this.random = random;
		this.g0 = g0;
		this.g1 = g1;
		this.h0 = h0;
		this.h1 = h1;
		
		// This protocol has no pre process stage.
	}

	/**
	 * Runs the part of the protocol where the sender's input is necessary as follows:<p>
	 *	WAIT for message (g,h) from R
	 *	COMPUTE (u0,v0) = RAND(g0,g,h0,h)
	 *	COMPUTE (u1,v1) = RAND(g1,g,h1,h)		
	 *	COMPUTE:<p> 
	 *		in the byte array scenario<p>
	 *			•   c0 = x0 XOR KDF(|x0|,v0)
	 *			•   c1 = x1 XOR KDF(|x1|,v1)
	 *		OR in the GroupElement scenario:<p>
	 *			•	c0 = x0 * v0<p>
	 *			•	c1 = x1 * v1<p>
	 *	SEND (u0,c0) and (u1,c1) to R<p>
	 *	OUTPUT nothing<p>
	 * The transfer stage of OT protocol which can be called several times in parallel.
	 * In order to enable the parallel calls, each transfer call should use a different channel to send and receive messages.
	 * This way the parallel executions of the function will not block each other.
	 * The parameters given in the input must match the DlogGroup member of this class, which given in the constructor.
	 * @param channel 
	 * @param input
	 * @throws IOException if failed to send the message.
	 * @throws ClassNotFoundException 
	 */
	public void transfer(Channel channel, OTSInput input) throws IOException, NullPointerException, ClassNotFoundException{
		//Wait for message (g,h) from R
		OTRMsg message = waitForMessageFromReceiver(channel);
		GroupElement g = dlog.reconstructElement(true, message.getFirstGE());
		GroupElement h = dlog.reconstructElement(true, message.getSecondGE());
		
		//Compute (u0,v0) = RAND(g0,g,h0,h)
		//Compute (u1,v1) = RAND(g1,g,h1,h)
		RandOutput tuple0 = OTUtil.rand(dlog, g0, g, h0, h, random);
		RandOutput tuple1 = OTUtil.rand(dlog, g1, g, h1, h, random);
		GroupElement u0 = tuple0.getU();
		GroupElement v0 = tuple0.getV();
		GroupElement u1 = tuple1.getU();
		GroupElement v1 = tuple1.getV();
		
		//Compute c0, c1.
		OTSMsg messageToSend = computeTuple(input, u0, u1, v0, v1);
		
		sendTupleToReceiver(channel, messageToSend);
	
	}
	
	/**
	 * Runs the following line from the protocol:
	 * "WAIT for message (h0,h1) from R"
	 * @param channel 
	 * @return the received message.
	 * @throws ClassNotFoundException 
	 * @throws IOException if failed to receive a message.
	 */
	private OTRMsg waitForMessageFromReceiver(Channel channel) throws ClassNotFoundException, IOException{
		Serializable message = null;
		try {
			message = channel.receive();
		} catch (IOException e) {
			throw new IOException("Failed to receive message. The thrown message is: " + e.getMessage());
		}
		if (!(message instanceof OTRMsg)){
			throw new IllegalArgumentException("The received message should be an instance of OTSMessage");
		}
		return (OTRMsg) message;
	}

	/**
	 * Runs the following lines from the protocol:
	 * "COMPUTE: in the byte array scenario:
	 *			•   c0 = x0 XOR KDF(|x0|,v0)
	 *			•   c1 = x1 XOR KDF(|x1|,v1)
	 *		OR in the GroupElement scenario:<p>
	 *			•	c0 = x0 * v0<p>
	 *			•	c1 = x1 * v1<p>
	 * @param v1 
	 * @param v0 
	 * @param u1 
	 * @param u0 
	 * @param input 
	 * @return tuple contains (u, v0, v1) to send to the receiver.
	 */
	protected abstract OTSMsg computeTuple(OTSInput input, GroupElement u0, GroupElement u1, GroupElement v0, GroupElement v1);

	/**
	 * Runs the following lines from the protocol:
	 * "SEND (u,v0,v1) to R"
	 * @param channel 
	 * @param message to send to the receiver
	 * @throws IOException if failed to send the message.
	 */
	private void sendTupleToReceiver(Channel channel, OTSMsg message) throws IOException {

		try {
			//Send the message by the channel.
			channel.send(message);
		} catch (IOException e) {
			throw new IOException("failed to send the message. The thrown message is: " + e.getMessage());
		}	
	}

}
