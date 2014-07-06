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
package edu.biu.scapi.interactiveMidProtocols.ot.fullSimulation;

import java.io.IOException;
import java.io.Serializable;
import java.security.SecureRandom;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.interactiveMidProtocols.ot.OTRGroupElementPairMsg;
import edu.biu.scapi.interactiveMidProtocols.ot.OTSInput;
import edu.biu.scapi.interactiveMidProtocols.ot.OTSMsg;
import edu.biu.scapi.interactiveMidProtocols.ot.OTUtil;
import edu.biu.scapi.interactiveMidProtocols.ot.OTUtil.RandOutput;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;

/**
 * This class execute the common functionality of the transfer function of all OT's that achieve full simulation. 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public abstract class OTFullSimSenderTransferUtilAbs {

	protected DlogGroup dlog;
	private SecureRandom random;
	
	/**
	 * Sets the given dlog and random.
	 * @param dlog
	 * @param random
	 */
	public OTFullSimSenderTransferUtilAbs(DlogGroup dlog, SecureRandom random){
		this.dlog = dlog;
		this.random = random;	
	}
	
	
	/**
	 * Runs the transfer phase of the OT protocol.<p>
	 * Transfer Phase (with inputs x0,x1)<p>
	 *	WAIT for message from R<p>
	 *	DENOTE the values received by (g,h) <p>
	 *	COMPUTE (u0,v0) = RAND(g0,g,h0,h)<p>
	 *	COMPUTE (u1,v1) = RAND(g1,g,h1,h)<p>
	 *	in the byte array scenario:<p>
	 *		COMPUTE c0 = x0 XOR KDF(|x0|,v0)<p>
	 *		COMPUTE c1 = x1 XOR KDF(|x1|,v1)<p>
	 *	in the GroupElement scenario:<p>
	 *		COMPUTE c0 = x0 * v0<p>
	 *		COMPUTE c1 = x1 * v1<p>
	 *	SEND (u0,c0) and (u1,c1) to R<p>
	 *	OUTPUT nothing<p>
	 * This is the transfer stage of OT protocol which can be called several times in parallel.<p>
	 * The OT implementation support usage of many calls to transfer, with single preprocess execution. <p>
	 * This way, one can execute batch OT by creating the OT receiver once and call the transfer function for each input couple.<p>
	 * In order to enable the parallel calls, each transfer call should use a different channel to send and receive messages.
	 * This way the parallel executions of the function will not block each other.
	 * @param channel each call should get a different one.
	 * @param input the parameters given in the input must match the DlogGroup member of this class, which given in the constructor.
	 * @param preprocessValues hold the values calculated in the preprocess phase.
	 * @return OTROutput, the output of the protocol.
	 * @throws CheatAttemptException if there was a cheat attempt during the execution of the protocol.
	 * @throws IOException if the send or receive functions failed
	 * @throws ClassNotFoundException if there was a problem during the serialization mechanism
	 */
	public void transfer(Channel channel, OTSInput input, OTFullSimPreprocessPhaseValues preprocessValues) throws IOException, ClassNotFoundException{
		
		//Wait for message from R
		OTRGroupElementPairMsg message = waitForMessageFromReceiver(channel);
				
		GroupElement g = dlog.reconstructElement(true, message.getFirstGE());
		GroupElement h = dlog.reconstructElement(true, message.getSecondGE());
		
		//COMPUTE (u0,v0) = RAND(g0,g,h0,h)
		//COMPUTE (u1,v1) = RAND(g1,g,h1,h)
		GroupElement g0 = preprocessValues.getG0(); //Get the group generator.
		RandOutput tuple0 = OTUtil.rand(dlog, g0, g, preprocessValues.getH0(), h, random);
		RandOutput tuple1 = OTUtil.rand(dlog, preprocessValues.getG1(), g, preprocessValues.getH1(), h, random);
		GroupElement u0 = tuple0.getU();
		GroupElement v0 = tuple0.getV();
		GroupElement u1 = tuple1.getU();
		GroupElement v1 = tuple1.getV();
		
		//Compute c0, c1.
		OTSMsg tuple = computeTuple(input, u0, u1, v0, v1);
		
		//Send the tuple for the receiver.
		sendTupleToReceiver(channel, tuple);
	
	}
	
	/**
	 * Runs the following line from the protocol:
	 * "WAIT for message (h0,h1) from R"
	 * @param channel
	 * @return the received message.
	 * @throws ClassNotFoundException 
	 * @throws IOException if failed to receive a message.
	 */
	private OTRGroupElementPairMsg waitForMessageFromReceiver(Channel channel) throws ClassNotFoundException, IOException{
		Serializable message = null;
		try {
			message = channel.receive();
		} catch (IOException e) {
			throw new IOException("Failed to receive message. The thrown message is: " + e.getMessage());
		}
		if (!(message instanceof OTRGroupElementPairMsg)){
			throw new IllegalArgumentException("The received message should be an instance of OTRMessage");
		}
		return (OTRGroupElementPairMsg) message;
	}
	
	/**
	 * Runs the following lines from the protocol:
	 * "COMPUTE:
	 * 		in the byte array scenario:
	 *			COMPUTE c0 = x0 XOR KDF(|x0|,v0)
	 *			COMPUTE c1 = x1 XOR KDF(|x1|,v1)
	 *		in the GroupElement scenario:
	 *			COMPUTE c0 = x0 * v0
	 *			COMPUTE c1 = x1 * v1
	 *		SEND (u0,c0) and (u1,c1) to R
	 *		OUTPUT nothing
	 * @param input
	 * @param v1 
	 * @param v0 
	 * @param u1 
	 * @param u0 
	 * @return tuple contains (u, v0, v1) to send to the receiver.
	 */
	protected abstract OTSMsg computeTuple(OTSInput input, GroupElement u0, GroupElement u1, GroupElement v0, GroupElement v1);

	/**
	 * Runs the following lines from the protocol:
	 * "SEND (u0,c0) and (u1,c1) to R"
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
