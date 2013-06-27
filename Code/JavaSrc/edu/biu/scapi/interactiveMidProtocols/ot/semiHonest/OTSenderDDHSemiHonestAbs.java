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
package edu.biu.scapi.interactiveMidProtocols.ot.semiHonest;

import java.io.IOException;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.util.BigIntegers;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.SecurityLevelException;
import edu.biu.scapi.interactiveMidProtocols.ot.OTSMessage;
import edu.biu.scapi.interactiveMidProtocols.ot.OTSender;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.dlog.cryptopp.CryptoPpDlogZpSafePrime;
import edu.biu.scapi.primitives.dlog.miracl.MiraclDlogECF2m;
import edu.biu.scapi.securityLevel.DDH;

/**
 * Abstract class for Semi-Honest OT assuming DDH sender.
 * Semi-Honest OT have two modes: one is on ByteArray and the second is on GroupElement.
 * The different is in the input and output types and the way to process them. 
 * In spite that, there is a common behavior for both modes which this class is implementing.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public abstract class OTSenderDDHSemiHonestAbs implements OTSender{
	
	/*	
	  This class runs the following protocol:
		 	WAIT for message (h0,h1) from R
			SAMPLE a random value r in  [0, . . . , q-1] 
			COMPUTE:
				•	u = g^r
				•	k0 = h0^r
				•	v0 = x0 XOR KDF(|x0|,k0) - in byteArray scenario.
						OR x0*k0			 - in GroupElement scenario.
				•	k1 = h1^r
				•	v1 = x1 XOR KDF(|x1|,k1) - in byteArray scenario.
						OR x1*k1 			 - in GroupElement scenario.
			SEND (u,v0,v1) to R
			OUTPUT nothing
	*/	 

	private Channel channel;
	protected DlogGroup dlog;
	private SecureRandom random;
	private BigInteger qMinusOne;
	
	//Values required for the tuple calculation:
	protected GroupElement u;	
	protected GroupElement k0;
	protected GroupElement k1;
	
	/**
	 * Constructor that gets the channel and chooses default values of DlogGroup and SecureRandom.
	 */
	public OTSenderDDHSemiHonestAbs(Channel channel){
		try{
			
			try {
				//Uses Miracl Koblitz 233 Elliptic curve.
				setMembers(channel, new MiraclDlogECF2m("K-233"), new SecureRandom());
			} catch (IOException e) {
				//If there is a problem with the elliptic curves file, create Zp DlogGroup.
				setMembers(channel, new CryptoPpDlogZpSafePrime(), new SecureRandom());
			}
		} catch (SecurityLevelException e) {
			// Can not occur since the DlogGroup is DDH secure
		}
	}
	
	/**
	 * Constructor that sets the given channel, dlogGroup and random.
	 * @param channel
	 * @param dlog must be DDH secure.
	 * @param random
	 * @throws SecurityLevelException if the given dlog is not DDH secure
	 */
	public OTSenderDDHSemiHonestAbs(Channel channel, DlogGroup dlog, SecureRandom random) throws SecurityLevelException{
		
		setMembers(channel, dlog, random);
	}
	
	/**
	 * Sets the given members.
	 * @param channel
	 * @param dlog must be DDH secure.
	 * @param random
	 * @throws SecurityLevelException if the given dlog is not DDH secure.
	 */
	private void setMembers(Channel channel, DlogGroup dlog, SecureRandom random) throws SecurityLevelException {
		//The underlying dlog group must be DDH secure.
		if (!(dlog instanceof DDH)){
			throw new SecurityLevelException("DlogGroup should have DDH security level");
		}
		
		this.channel = channel;
		this.dlog = dlog;
		this.random = random;
		qMinusOne =  dlog.getOrder().subtract(BigInteger.ONE);
	}
	
	/**
	 * Runs the part of the protocol where the sender input is not yet necessary.
	 * @throws IOException if failed to receive a message.
	 * @throws ClassNotFoundException 
	 */
	public void preProcess() throws ClassNotFoundException, IOException{
		/* Runs the following part of the protocol:
				WAIT for message (h0,h1) from R
				SAMPLE a random value r in  [0, . . . , q-1] 
				COMPUTE:
					•	u = g^r
					•	k0 = h0^r
					•	k1 = h1^r
		*/
		OTRSemiHonestMessage message = waitForMessageFromReceiver();
		BigInteger r = sampleRandomValues();
		computePreProcessValues(r, message);
	}

	/**
	 * Runs the part of the protocol where the sender input is necessary.
	 * @throws IOException if failed to send the message.
	 */
	public void transfer() throws IOException{
		/* Runs the following part of the protocol:
				COMPUTE: in the byte array scenario
					•	v0 = x0 XOR KDF(|x0|,k0) 
					•	v1 = x1 XOR KDF(|x1|,k1) 
				OR in the GroupElement scenario:
	 				•	v0 = x0 * k0
	 				•	v1 = x1 * k1"
				SEND (u,v0,v1) to R
				OUTPUT nothing
		*/
		try{
			
			OTSMessage message = computeTuple();
			sendTupleToReceiver(message);
		
		}catch(NullPointerException e){
			throw new IllegalStateException("preProcess function should be called before transfer atleast once");
		}
		
	}

	/**
	 * Runs the following line from the protocol:
	 * "WAIT for message (h0,h1) from R"
	 * @return the received message.
	 * @throws ClassNotFoundException 
	 * @throws IOException if failed to receive a message.
	 */
	private OTRSemiHonestMessage waitForMessageFromReceiver() throws ClassNotFoundException, IOException{
		Serializable message = null;
		try {
			message = channel.receive();
		} catch (IOException e) {
			throw new IOException("failed to receive message. The thrown message is: " + e.getMessage());
		}
		if (!(message instanceof OTRSemiHonestMessage)){
			throw new IllegalArgumentException("the given message should be an instance of OTSMessage");
		}
		return (OTRSemiHonestMessage) message;
	}
	
	/**
	 * Runs the following line from the protocol:
	 * "SAMPLE a random value r in  [0, . . . , q-1]"
	 * @return the chosen BigInteger.
	 */
	private BigInteger sampleRandomValues() {
		BigInteger r = BigIntegers.createRandomInRange(BigInteger.ZERO, qMinusOne, random);
		return r;
	}
	
	/**
	 * Runs the following lines from the protocol:
	 * "COMPUTE:
	 *		•	u = g^r
	 *		•	k0 = h0^r
	 *		•	k1 = h1^r"
	 * @param r the exponent
	 * @param message contains h0, h1
	 */
	private void computePreProcessValues(BigInteger r, OTRSemiHonestMessage message) {
		GroupElement g = dlog.getGenerator(); //Get the group generator.
		
		//Calculate u = g^r.
		u = dlog.exponentiate(g, r);
		GroupElement h0, h1;
		
		//Recreate h0, h1 from the data in the received message.
		h0 = dlog.reconstructElement(true, message.getH0());
		h1 = dlog.reconstructElement(true, message.getH1());
		
		//Calculate k0 = h0^r and k1 = h1^r.
		k0 = dlog.exponentiate(h0, r);
		k1 = dlog.exponentiate(h1, r);
		
	}
	
	/**
	 * Runs the following lines from the protocol:
	 * "COMPUTE: in the byte array scenario:
	 *		•	v0 = x0 XOR KDF(|x0|,k0) 
	 *		•	v1 = x1 XOR KDF(|x1|,k1)
	 * OR in the GroupElement scenario:
	 * 		•	v0 = x0 * k0
	 *		•	v1 = x1 * k1"
	 * @return tuple contains (u, v0, v1) to send to the receiver.
	 */
	protected abstract OTSMessage computeTuple();
		
	/**
	 * Runs the following lines from the protocol:
	 * "SEND (u,v0,v1) to R"
	 * @param message to send to the receiver
	 * @throws IOException if failed to send the message.
	 */
	private void sendTupleToReceiver(OTSMessage message) throws IOException {
		
		try {
			//Send the message by the channel.
			channel.send(message);
		} catch (IOException e) {
			throw new IOException("failed to send the message. The thrown message is: " + e.getMessage());
		}	
	}
}
