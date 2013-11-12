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
import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.util.BigIntegers;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.interactiveMidProtocols.ot.OTRBasicInput;
import edu.biu.scapi.interactiveMidProtocols.ot.OTRGroupElementPairMsg;
import edu.biu.scapi.interactiveMidProtocols.ot.OTRInput;
import edu.biu.scapi.interactiveMidProtocols.ot.OTROutput;
import edu.biu.scapi.interactiveMidProtocols.ot.OTSMsg;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;

/**
 * This class execute the common functionality of the transfer function of all OT's that achieve full simulation. 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public abstract class OTFullSimReceiverTransferUtilAbs {
	
	protected DlogGroup dlog;
	private SecureRandom random;
	private BigInteger qMinusOne;
	
	/**
	 * Sets the given dlog and random.
	 * @param dlog
	 * @param random
	 */
	public OTFullSimReceiverTransferUtilAbs(DlogGroup dlog, SecureRandom random){
		this.dlog = dlog;
		this.random = random;
		qMinusOne =  dlog.getOrder().subtract(BigInteger.ONE);
	}
	
	
	
	/**
	 * 
	 * Run the transfer phase of the OT protocol.<p>
	 * Transfer Phase (with inputs sigma) <p>
	 *		SAMPLE a random value r <- {0, . . . , q-1} <p>
	 *		COMPUTE<p>
	 *		4.	g = (gSigma)^r<p>
	 *		5.	h = (hSigma)^r<p>
	 *		SEND (g,h) to S<p>
	 *		WAIT for messages (u0,c0) and (u1,c1) from S<p>
	 *		In ByteArray scenario:<p>
	 *		IF  NOT<p>
	 *		•	u0, u1 in G, AND<p>
	 *		•	c0, c1 are binary strings of the same length<p>
	 *		      REPORT ERROR<p>
	 *		OUTPUT  xSigma = cSigma XOR KDF(|cSigma|,(uSigma)^r)<p>
	 *		In GroupElement scenario:<p>
	 *		IF  NOT<p>
	 *		•	u0, u1, c0, c1 in G<p>
	 *		      REPORT ERROR<p>
	 *		OUTPUT  xSigma = cSigma * (uSigma)^(-r)<p>
	 * This is the transfer stage of OT protocol which can be called several times in parallel.<p>
	 * The OT implementation support usage of many calls to transfer, with single preprocess execution. <p>
	 * This way, one can execute batch OT by creating the OT receiver once and call the transfer function for each input couple.<p>
	 * In order to enable the parallel calls, each transfer call should use a different channel to send and receive messages.
	 * This way the parallel executions of the function will not block each other.
	 * @param channel each call should get a different one.
	 * @param input MUST be OTRBasicInput. The parameters given in the input must match the DlogGroup member of this class, which given in the constructor.
	 * @param preprocessValues hold the values calculated in the preprocess phase.
	 * @return OTROutput, the output of the protocol.
	 * @throws CheatAttemptException if there was a cheat attempt during the execution of the protocol.
	 * @throws IOException if the send or receive functions failed
	 * @throws ClassNotFoundException if there was a problem during the serialization mechanism
	 */
	public OTROutput transfer(Channel channel, OTRInput input, OTFullSimPreprocessPhaseValues preprocessValues) throws IOException, ClassNotFoundException, CheatAttemptException {
		//check if the input is valid.
		//If input is not instance of OTRBasicInput, throw Exception.
		if (!(input instanceof OTRBasicInput)){
			throw new IllegalArgumentException("input should contain sigma.");
		}
		
		byte sigma = ((OTRBasicInput) input).getSigma();
		
		//The given sigma should be 0 or 1.
		if ((sigma != 0) && (sigma!= 1)){
			throw new IllegalArgumentException("Sigma should be 0 or 1");
		}
		
		//Sample a random value r <- {0, . . . , q-1} 
		BigInteger r = BigIntegers.createRandomInRange(BigInteger.ZERO, qMinusOne, random);
		
		//Compute tuple (g,h) for sender.
		OTRGroupElementPairMsg a = computeSecondTuple(sigma, r, preprocessValues);
		
		//Send tuple to sender.
		sendTupleToSender(channel, a);
		
		//Wait for message from sender.
		OTSMsg message = waitForMessageFromSender(channel);
		
		//Compute the final calculations to get xSigma.
		return checkMessgeAndComputeX(sigma, r, message);
	}
	
	/**
	 * Runs the following lines from the protocol:
	 * "COMPUTE 
	 * 4.	g = (gSigma)^r
	 * 5.	h = (hSigma)^r"
	 * @param sigma input of the protocol
	 * @param r random value sampled in the protocol
	 * @return OTRFullSimMessage contains the tuple (g,h).
	 */
	private OTRGroupElementPairMsg computeSecondTuple(byte sigma, BigInteger r, OTFullSimPreprocessPhaseValues preprocessValues) {
		GroupElement g, h;
		
		if (sigma == 0){
			g = dlog.exponentiate(preprocessValues.getG0(), r);
			h = dlog.exponentiate(preprocessValues.getH0(), r);
		}
		else {
			g = dlog.exponentiate(preprocessValues.getG1(), r);
			h = dlog.exponentiate(preprocessValues.getH1(), r);
		}
		
		return new OTRGroupElementPairMsg(g.generateSendableData(), h.generateSendableData());
	}
	
	/**
	 * Runs the following line from the protocol:
	 * "SEND tuple to S"
	 * @param channel
	 * @param a the tuple to send to the sender.
	 * @throws IOException 
	 */
	private static void sendTupleToSender(Channel channel, Serializable a) throws IOException {
		try {
			channel.send(a);
		} catch (IOException e) {
			throw new IOException("failed to send the message. The thrown message is: " + e.getMessage());
		}
		
	}
	
	/**
	 * Runs the following line from the protocol:
	 * "WAIT for message pairs (w0, c0) and (w1, c1)  from S"
	 * @param channel
	 * @return OTSMessage contains (w0, c0, w1, c1)
	 * @throws IOException if failed to receive.
	 * @throws ClassNotFoundException
	 */
	private OTSMsg waitForMessageFromSender(Channel channel) throws IOException, ClassNotFoundException {
		Serializable message = null;
		try {
			message =  channel.receive();
		} catch (IOException e) {
			throw new IOException("failed to receive message. The thrown message is: " + e.getMessage());
		}
		if (!(message instanceof OTSMsg)){
			throw new IllegalArgumentException("the given message should be an instance of OTSMessage");
		}
		return (OTSMsg) message;
	}
	
	/**
	 * Runs the following lines from the protocol:
	 * "In ByteArray scenario:
	 *		IF  NOT 
	 *			1. w0, w1 in the DlogGroup, AND
	 *			2. c0, c1 are binary strings of the same length
	 *		   REPORT ERROR
	 *		OUTPUT  xSigma = cSigma XOR KDF(|cSigma|,(uSigma)^r)
	 *	In GroupElement scenario:
	 *		IF  NOT 
	 *			1. w0, w1, c0, c1 in the DlogGroup
	 *		   REPORT ERROR
	 *	OUTPUT  xSigma = cSigma * (uSigma)^(-r)"
	 * @param sigma input of the protocol
	 * @param r random value sampled in the protocol
	 * @param message received from the sender
	 * @return OTROutput contains xSigma
	 * @throws CheatAttemptException 
	 */
	protected abstract OTROutput checkMessgeAndComputeX(byte sigma, BigInteger r, OTSMsg message) throws CheatAttemptException;

	
}
