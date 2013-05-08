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
import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.util.BigIntegers;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.interactiveMidProtocols.ot.OTRBasicInput;
import edu.biu.scapi.interactiveMidProtocols.ot.OTRInput;
import edu.biu.scapi.interactiveMidProtocols.ot.OTROutput;
import edu.biu.scapi.interactiveMidProtocols.ot.OTReceiver;
import edu.biu.scapi.interactiveMidProtocols.ot.OTSMessage;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.dlog.cryptopp.CryptoPpDlogZpSafePrime;
import edu.biu.scapi.primitives.dlog.miracl.MiraclDlogECF2m;
import edu.biu.scapi.securityLevel.DDH;

/**
 * Abstract class for Semi-Honest OT assuming DDH receiver.
 * Semi-Honest OT have two modes: one is on ByteArray and the second is on GroupElement.
 * The different is in the input and output types and the way to process them. 
 * In spite that, there is a common behavior for both modes which this class is implementing.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public abstract class OTReceiverDDHSemiHonestAbs implements OTReceiver{
	/*	
	 	This class runs the following protocol:
		 	SAMPLE random values alpha in Zq and h in the DlogGroup 
			COMPUTE h0,h1 as follows:
				1.	If σ = 0 then h0 = g^alpha  and h1 = h
				2.	If σ = 1 then h0 = h and h1 = g^alpha 
			SEND (h0,h1) to S
			WAIT for the message (u, v0,v1) from S
			COMPUTE kσ = (u)^alpha					- in byte array scenario
				 OR (kσ)^(-1) = u^(-alpha)			- in GroupElement scenario
			OUTPUT  xσ = vσ XOR KDF(|cσ|,kσ)		- in byte array scenario
				 OR xσ = vσ * (kσ)^(-1) 			- in GroupElement scenario
	*/	
	
	private Channel channel;
	protected DlogGroup dlog;
	private SecureRandom random;
	
	//Values required for calculations:
	protected short sigma;
	BigInteger alpha;
	private GroupElement gAlpha;
	private GroupElement h;
	
	/**
	 * Constructor that gets the channel and chooses default values of DlogGroup and SecureRandom.
	 */
	public OTReceiverDDHSemiHonestAbs(Channel channel){
		try {
			//Uses Miracl Koblitz 233 Elliptic curve.
			setMembers(channel, new MiraclDlogECF2m("K-233"), new SecureRandom());
		} catch (IOException e) {
			//If there is a problem with the elliptic curves file, create Zp DlogGroup.
			setMembers(channel, new CryptoPpDlogZpSafePrime(), new SecureRandom());
		}
	}

	/**
	 * Constructor that sets the given channel, dlogGroup and random.
	 * @param channel
	 * @param dlog must be DDH secure.
	 * @param random
	 */
	public OTReceiverDDHSemiHonestAbs(Channel channel, DlogGroup dlog, SecureRandom random){
		
		setMembers(channel, dlog, random);
	}
	
	/**
	 * Sets the given members.
	 * @param channel
	 * @param dlog must be DDH secure.
	 * @param random
	 */
	private void setMembers(Channel channel, DlogGroup dlog, SecureRandom random) {
		//The underlying dlog group must be DDH secure.
		if (!(dlog instanceof DDH)){
			throw new IllegalArgumentException("DlogGroup should have DDH security level");
		}
		
		this.channel = channel;
		this.dlog = dlog;
		this.random = random;
		
	}
	
	/**
	 * Runs the part of the protocol where the receiver input is not yet necessary.
	 */
	public void preProcess(){
		/* Run the following part of the protocol:
				SAMPLE random values alpha in  [0, . . . , q-1]  and h in the DlogGroup. 
				COMPUTE g^alpha 
		*/
		
		//Sample random values.
		sampleRandomValues();
		
		//Calculate g^σ.
		GroupElement g = dlog.getGenerator();
		gAlpha = dlog.exponentiate(g, alpha);
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
	 * Runs the part of the protocol where the receiver input is necessary.
	 * @return OTROutput, the output of the protocol.
	 */
	public OTROutput transfer(){
		/* Run the following part of the protocol:
				COMPUTE h0,h1 as follows:
					1.	If σ = 0 then h0 = g^alpha  and h1 = h
					2.	If σ = 1 then h0 = h and h1 = g^alpha 
				SEND (h0,h1) to S
				WAIT for the message (u, v0,v1) from S
				COMPUTE kσ = (u)^alpha					- in byte array scenario
					OR (kσ)^(-1) = u^(-alpha)			- in GroupElement scenario
				OUTPUT  xσ = vσ XOR KDF(|cσ|,kσ)		- in byte array scenario
					 OR xσ = vσ * (kσ)^(-1) 			- in GroupElement scenario
		*/
		
		OTRSemiHonestMessage tuple = computeTuple();
		sendTupleToSender(tuple);
		OTSMessage message = waitForMessageFromSender();
		return computeFinalXSigma(message);
		
	}
	
	/**
	 * Runs the following lines from the protocol:
	 * "SAMPLE random values alpha in  [0, . . . , q-1]  and h in the DlogGroup". 
	 */
	private void sampleRandomValues() {
		//Sample random alpha.
		BigInteger qMinusOne =  dlog.getOrder().subtract(BigInteger.ONE);
		alpha = BigIntegers.createRandomInRange(BigInteger.ZERO, qMinusOne, random);
		
		//Sample random h.
		h = dlog.createRandomElement();
	}

	/**
	 * Runs the following lines from the protocol:
	 * "COMPUTE h0,h1 as follows:
	 *		1.	If σ = 0 then h0 = g^alpha  and h1 = h
	 *		2.	If σ = 1 then h0 = h and h1 = g^alpha"
	 * @return OTRSemiHonestMessage contains the tuple (h0, h1).
	 */
	private OTRSemiHonestMessage computeTuple() {
		GroupElement h0 = null;
		GroupElement h1 = null;
		if (sigma == 0){
			h0 = gAlpha;
			h1 = h;
		}
		if (sigma == 1){
			h0 = h;
			h1 = gAlpha;
		}
		return new OTRSemiHonestMessage(h0.generateSendableData(), h1.generateSendableData());
	}
	
	/**
	 * Runs the following line from the protocol:
	 * "SEND (h0,h1) to S"
	 * @param tuple to send to the sender
	 */
	private void sendTupleToSender(OTRSemiHonestMessage tuple) {
		try {
			channel.send(tuple);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	
	/**
	 * Runs the following line from the protocol:
	 * "WAIT for the message (u, v0,v1) from S"
	 * @return OTSMessage contains (u, v0,v1)
	 */
	private OTSMessage waitForMessageFromSender() {
		try {
			return (OTSMessage) channel.receive();
		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
	
	/**
	 * Runs the following lines from the protocol:
	 * "COMPUTE kσ = (u)^alpha					- in byte array scenario
	 *		OR (kσ)^(-1) = u^(-alpha)			- in GroupElement scenario
	 *		OUTPUT  xσ = vσ XOR KDF(|cσ|,kσ)	- in byte array scenario
	 *		 	 OR xσ = vσ * (kσ)^(-1)" 		- in GroupElement scenario
	 * @param message received from the sender
	 * @return OTROutput contains Xσ
	 */
	protected abstract OTROutput computeFinalXSigma(OTSMessage message);
}
