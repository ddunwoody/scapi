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
import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.util.BigIntegers;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.exceptions.SecurityLevelException;
import edu.biu.scapi.interactiveMidProtocols.ot.OTRBasicInput;
import edu.biu.scapi.interactiveMidProtocols.ot.OTRInput;
import edu.biu.scapi.interactiveMidProtocols.ot.OTRMessage;
import edu.biu.scapi.interactiveMidProtocols.ot.OTROutput;
import edu.biu.scapi.interactiveMidProtocols.ot.OTReceiver;
import edu.biu.scapi.interactiveMidProtocols.ot.OTSMessage;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.dlog.cryptopp.CryptoPpDlogZpSafePrime;
import edu.biu.scapi.primitives.dlog.miracl.MiraclDlogECF2m;
import edu.biu.scapi.securityLevel.DDH;
import edu.biu.scapi.securityLevel.UC;

/**
 * Abstract class for oblivious transfer receiver based on the DDH assumption that achieves UC security in
 * the common reference string model.
 * This OT has two modes: one is on ByteArray and the second is on GroupElement.
 * The difference is in the input and output types and the way to process them. 
 * In spite that, there is a common behavior for both modes which this class implements.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public abstract class OTReceiverDDHUCAbs implements OTReceiver, UC{
	/*	
 	This class runs the following protocol:
	 	SAMPLE a random value r <- {0, . . . , q-1} 
		COMPUTE g = (gSigma)r and h = (hSigma)r
		SEND (g,h) to S
		WAIT for messages (u0,c0) and (u1,c1) from S
		In Byte Array scenario:
			IF  NOT
			•	u0, u1 in G, AND
			•	c0, c1 are binary strings of the same length
			      REPORT ERROR
			OUTPUT  xSigma = cSigma XOR KDF(|cSigma|,(uSigma)^r)
		In GroupElement scenario:
			IF  NOT
			•	u0, u1, c0, c1 in G
			      REPORT ERROR
			OUTPUT  xSigma = cSigma * (uSigma)^(-r)
	*/
	
	private Channel channel;
	protected DlogGroup dlog;
	private SecureRandom random;
	private BigInteger qMinusOne;
	private GroupElement g0, g1, h0, h1;
	
	//Values required for calculations:
	protected short sigma;
	protected BigInteger r;
	protected GroupElement u0, u1;
	
	/**
	 * Constructor that sets the given channel and choose default values to the other parameters.
	 * @param channel
	 */
	public OTReceiverDDHUCAbs(Channel channel){
		
		
			DlogGroup dlog;
			try {
				//Uses Miracl Koblitz 233 Elliptic curve.
				dlog = new MiraclDlogECF2m("K-233");
			} catch (IOException e) {
				dlog = new CryptoPpDlogZpSafePrime();
			} 
		
		GroupElement g0 = dlog.getGenerator();
		GroupElement g1 = dlog.createRandomElement();
		GroupElement h0 = dlog.createRandomElement();
		GroupElement h1 = dlog.createRandomElement();
		try {
			setMembers(channel, dlog, g0, g1, h0, h1, new SecureRandom());
		} catch (SecurityLevelException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	/**
	 * Constructor that sets the given channel, common reference string composed of a DLOG 
	 * description (G,q,g0) and (g0,g1,h0,h1) which is a randomly chosen non-DDH tuple, 
	 * kdf and random.
	 * @param channel
	 * @param dlog must be DDH secure.
	 * @param g0 
	 * @param g1 
	 * @param h0 
	 * @param h1 
	 * @param kdf
	 * @param random
	 * @throws SecurityLevelException if the given dlog is not DDH secure.
	 */
	public OTReceiverDDHUCAbs(Channel channel, DlogGroup dlog, GroupElement g0, GroupElement g1, 
			GroupElement h0, GroupElement h1, SecureRandom random) throws SecurityLevelException{
		setMembers(channel, dlog, g0, g1, h0, h1, random);
		
	}
	
	/**
	 * Sets the given parameters.
	 * @param channel
	 * @param dlog must be DDH secure.
	 * @param g0
	 * @param g1
	 * @param h0
	 * @param h1
	 * @param random
	 * @throws SecurityLevelException if the given dlog is not DDH secure.
	 */
	private void setMembers(Channel channel, DlogGroup dlog, GroupElement g0, 
			GroupElement g1, GroupElement h0, GroupElement h1, SecureRandom random) throws SecurityLevelException{
		//The underlying dlog group must be DDH secure.
		if (!(dlog instanceof DDH)){
			throw new SecurityLevelException("DlogGroup should have DDH security level");
		}
		
		this.channel = channel;
		this.dlog = dlog;
		this.random = random;
		qMinusOne =  dlog.getOrder().subtract(BigInteger.ONE);
		this.g0 = g0;
		this.g1 = g1;
		this.h0 = h0;
		this.h1 = h1;
	}
	
	/**
	 * Runs the part of the protocol where the receiver input is not yet necessary as follows:
	 * "SAMPLE a random value r <- {0, . . . , q-1}".
	 */
	public void preProcess(){
		
		//Sample random value r.
		sampleRandomValues();
	}
	
	/**
	 * Sets the input for this OT receiver.
	 * @param input MUST be OTRBasicInput.
	 */
	public void setInput(OTRInput input) {
		//If input is not instance of OTRBasicInput, throw Exception.
		if (!(input instanceof OTRBasicInput)){
			throw new IllegalArgumentException("input shoud contain sigma.");
		}
		
		//The given sigma should be 0 or 1.
		if ((sigma != 0) && (sigma!= 1)){
			throw new IllegalArgumentException("Sigma should be 0 or 1");
		}
		//Set sigma.
		this.sigma = ((OTRBasicInput) input).getSigma();
	}
	
	/**
	 * Runs the part of the protocol where the receiver input is necessary as follows:
	 * "COMPUTE g = (gSigma)^r and h = (hSigma)^r
	 * SEND (g,h) to S
	 * WAIT for messages (u0,c0) and (u1,c1) from S
	 *	In Byte Array scenario:
	 *		IF  NOT
	 *		•	u0, u1 in G, AND
	 *		•	c0, c1 are binary strings of the same length
	 *			     REPORT ERROR
	 *		OUTPUT  xSigma = cSigma XOR KDF(|cSigma|,(uSigma)^r)
	 *	In GroupElement scenario:
	 *		IF  NOT
	 *		•	u0, u1, c0, c1 in G
	 *				 REPORT ERROR
	 *		OUTPUT  xSigma = cSigma * (uSigma)^(-r)".
	 * @return OTROutput, the output of the protocol.
	 * @throws IOException if failed to send or receive a message.
	 * @throws ClassNotFoundException
	 * @throws CheatAttemptException 
	 */
	public OTROutput transfer() throws IOException, ClassNotFoundException, CheatAttemptException{
		
		try{
			//Compute tuple for sender.
			OTRMessage a = computeTuple();
			
			//Send tuple to sender.
			sendTupleToSender(a);
			
			//Wait for message from sender.
			OTSMessage message = waitForMessageFromSender();
			
			//checked the received message.
			checkReceivedTuple(message);
			
			//Compute the final calculations to get xSigma.
			return computeFinalXSigma();
			
		}catch(NullPointerException e){
			throw new IllegalStateException("preProcess function should be called before transfer atleast once");
		}
		
	}
	
	/**
	 * Runs the following lines from the protocol:
	 * "SAMPLE a random value r <- {0, . . . , q-1} ". 
	 */
	private void sampleRandomValues() {
		//Sample random r.
		r = BigIntegers.createRandomInRange(BigInteger.ZERO, qMinusOne, random);
	}
	
	/**
	 * Runs the following lines from the protocol:
	 * "COMPUTE g = (gSigma)^r and h = (hSigma)^r"
	 * @return OTRSemiHonestMessage contains the tuple (h0, h1).
	 */
	private OTRMessage computeTuple() {
		GroupElement g = null;
		GroupElement h = null;
		if (sigma == 0){
			g = dlog.exponentiate(g0, r);
			h = dlog.exponentiate(h0, r);
		}
		if (sigma == 1){
			g = dlog.exponentiate(g1, r);
			h = dlog.exponentiate(h1, r);
		}
		return new OTRMessage(g.generateSendableData(), h.generateSendableData());
	}
	
	/**
	 * Runs the following line from the protocol:
	 * "SEND (h0,h1) to S"
	 * @param tuple to send to the sender
	 * @throws IOException if failed to send the message.
	 */
	private void sendTupleToSender(OTRMessage tuple) throws IOException {
		try {
			channel.send(tuple);
		} catch (IOException e) {
			throw new IOException("failed to send the message. The thrown message is: " + e.getMessage());
		}
		
	}
	
	/**
	 * Runs the following line from the protocol:
	 * "WAIT for the message (u, v0,v1) from S"
	 * @return OTSMessage contains (u, v0,v1)
	 * @throws ClassNotFoundException
	 * @throws IOException if failed to receive a message.
	 */
	private OTSMessage waitForMessageFromSender() throws ClassNotFoundException, IOException {
		Serializable message;
		try {
			message = channel.receive();
		} catch (IOException e) {
			throw new IOException("failed to receive message. The thrown message is: " + e.getMessage());
		}
		if (!(message instanceof OTSMessage)){
			throw new IllegalArgumentException("the given message should be an instance of OTSMessage");
		}
		return (OTSMessage) message;
	}
	
	/**
	 * Runs the following line from the protocol:
	 * "In Byte Array scenario:
	 *		IF  NOT
	 *		•	u0, u1 in G, AND
	 *		•	c0, c1 are binary strings of the same length
	 *			     REPORT ERROR
	 *		
	 *	In GroupElement scenario:
	 *		IF  NOT
	 *		•	u0, u1, c0, c1 in G
	 *				 REPORT ERROR"		
	 * @param message
	 * @throws CheatAttemptException 
	 */
	protected abstract void checkReceivedTuple(OTSMessage message) throws CheatAttemptException;
	
	/**
	 * Runs the following lines from the protocol:
	 * "In Byte Array scenario:
	 *		OUTPUT  xSigma = cSigma XOR KDF(|cSigma|,(uSigma)^r)
	 *	In GroupElement scenario:
	 *		OUTPUT  xSigma = cSigma * (uSigma)^(-r)".
	 * @return OTROutput contains xSigma
	 */
	protected abstract OTROutput computeFinalXSigma();

}
