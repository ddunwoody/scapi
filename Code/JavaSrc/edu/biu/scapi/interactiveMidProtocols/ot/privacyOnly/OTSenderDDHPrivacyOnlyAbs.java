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
package edu.biu.scapi.interactiveMidProtocols.ot.privacyOnly;

import java.io.IOException;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.util.BigIntegers;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.exceptions.InvalidDlogGroupException;
import edu.biu.scapi.exceptions.SecurityLevelException;
import edu.biu.scapi.interactiveMidProtocols.ot.OTSMessage;
import edu.biu.scapi.interactiveMidProtocols.ot.OTSender;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.dlog.cryptopp.CryptoPpDlogZpSafePrime;
import edu.biu.scapi.primitives.dlog.miracl.MiraclDlogECF2m;
import edu.biu.scapi.securityLevel.DDH;

/**
 * Abstract class for OT Privacy assuming DDH sender.
 * Privacy OT have two modes: one is on ByteArray and the second is on GroupElement.
 * The different is in the input and output types and the way to process them. 
 * In spite that, there is a common behavior for both modes which this class is implementing.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public abstract class OTSenderDDHPrivacyOnlyAbs implements OTSender{

	/*	
	  This class runs the following protocol:
			WAIT for message a from R
			DENOTE the tuple a received by S by (x, y, z0, z1)
			IF NOT
			•	z0 != z1
			•	x, y, z0, z1 in the DlogGroup
			REPORT ERROR (cheat attempt)
			SAMPLE random values u0,u1,v0,v1 in  {0, . . . , q-1} 
			COMPUTE:
			•	w0 = x^u0 • g^v0
			•	k0 = (z0)^u0 • y^v0
			•	w1 = x^u1 • g^v1
			•	k1 = (z1)^u1 • y^v1 
			in byteArray scenario:
				•	c0 = x0 XOR KDF(|x0|,k0)
				•	c1 = x1 XOR KDF(|x1|,k1) 
			OR in GroupElement scenario:
				•	c0 = x0 * k0
				•	c1 = x1 * k1
			SEND (w0, c0) and (w1, c1) to R
			OUTPUT nothing
	*/	 

	private Channel channel;
	protected DlogGroup dlog;
	private SecureRandom random;
	private BigInteger qMinusOne;
	
	//will be given in the receiver's message.
	private GroupElement x, y, z0, z1;
	
	//Values required for calculations:
	private BigInteger u0, u1, v0, v1;
	protected GroupElement w0, w1, k0, k1;
	
	/**
	 * Constructor that gets the channel and chooses default values of DlogGroup and SecureRandom.
	 */
	public OTSenderDDHPrivacyOnlyAbs(Channel channel){
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
		} catch (InvalidDlogGroupException e) {
			// Can not occur since the DlogGroup is valid.
		}
	}
	
	/**
	 * Constructor that sets the given channel, dlogGroup and random.
	 * @param channel
	 * @param dlog must be DDH secure.
	 * @param random
	 * @throws SecurityLevelException if the given dlog is not DDH secure
	 * @throws InvalidDlogGroupException if the given DlogGroup is not valid.
	 */
	public OTSenderDDHPrivacyOnlyAbs(Channel channel, DlogGroup dlog, SecureRandom random) throws SecurityLevelException, InvalidDlogGroupException{
		
		setMembers(channel, dlog, random);
	}
	
	/**
	 * Sets the given members.
	 * @param channel
	 * @param dlog must be DDH secure.
	 * @param random
	 * @throws SecurityLevelException if the given dlog is not DDH secure
	 * @throws InvalidDlogGroupException if the given DlogGroup is not valid.
	 */
	private void setMembers(Channel channel, DlogGroup dlog, SecureRandom random) throws SecurityLevelException, InvalidDlogGroupException {
		//The underlying dlog group must be DDH secure.
		if (!(dlog instanceof DDH)){
			throw new SecurityLevelException("DlogGroup should have DDH security level");
		}
		//Check that the given dlog is valid.
		if(!dlog.validateGroup())
			throw new InvalidDlogGroupException();
		
		this.channel = channel;
		this.dlog = dlog;
		this.random = random;
		qMinusOne =  dlog.getOrder().subtract(BigInteger.ONE);
		
	}
	
	/**
	 * Runs the part of the protocol where the sender input is not yet necessary.
	 * @throws CheatAttemptException if there was a cheat attempt during the execution of the protocol.
	 * @throws ClassNotFoundException 
	 * @throws IOException if failed to receive a message.
	 */
	public void preProcess() throws CheatAttemptException, IOException, ClassNotFoundException{
		/* Runs the following part of the protocol:
				WAIT for message a from R
				DENOTE the tuple a received by S by (x, y, z0, z1)
				IF NOT
				•	z0 != z1
				•	x, y, z0, z1 in the DlogGroup
				REPORT ERROR (cheat attempt)
				SAMPLE random values u0,u1,v0,v1 in  {0, . . . , q-1} 
				COMPUTE:
				•	w0 = x^u0 • g^v0
				•	k0 = (z0)^u0 • y^v0
				•	w1 = x^u1 • g^v1
				•	k1 = (z1)^u1 • y^v1 
		*/
		OTRPrivacyOnlyMessage message = waitForMessageFromReceiver();
		checkReceivedTuple(message);
		sampleRandomValues();
		computePreProcessValues();
	}

	/**
	 * Runs the part of the protocol where the sender input is necessary.
	 * @throws IOException if failed to send the message.
	 */
	public void transfer() throws IOException{
		/* Runs the following part of the protocol:
				COMPUTE: in byteArray scenario:
				•	c0 = x0 XOR KDF(|x0|,k0)
				•	c1 = x1 XOR KDF(|x1|,k1) 
				OR in GroupElement scenario:
				•	c0 = x0 * k0
				•	c1 = x1 * k1
				SEND (w0, c0) and (w1, c1) to R
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
	 * @throws IOException if failed to receive a message.
	 * @throws ClassNotFoundException 
	 */
	private OTRPrivacyOnlyMessage waitForMessageFromReceiver() throws IOException, ClassNotFoundException{
		Serializable message = null;
		try {
			message = channel.receive();
		} catch (IOException e) {
			throw new IOException("failed to receive message. The thrown message is: " + e.getMessage());
		}
		if (!(message instanceof OTRPrivacyOnlyMessage)){
			throw new IllegalArgumentException("the given message should be an instance of OTRPrivacyOnlyMessage");
		}
		return (OTRPrivacyOnlyMessage) message;
	}
	
	/**
	 * Runs the following lines from the protocol:
	 * "IF NOT
	 *	•	z0 != z1
	 *	•	x, y, z0, z1 in the DlogGroup
	 *	REPORT ERROR (cheat attempt)"
	 * @return the received message.
	 * @throws CheatAttemptException 
	 */
	private void checkReceivedTuple(OTRPrivacyOnlyMessage message) throws CheatAttemptException {
		//Reconstruct the group elements from the given message.
		x = dlog.reconstructElement(true, message.getX());
		y = dlog.reconstructElement(true, message.getY());
		z0 = dlog.reconstructElement(true, message.getZ0());
		z1 = dlog.reconstructElement(true, message.getZ1());
		
		if (!(dlog.isMember(x))){
			throw new CheatAttemptException("x element is not a member of the current DlogGroup");
		}
		if (!(dlog.isMember(y))){
			throw new CheatAttemptException("y element is not a member of the current DlogGroup");
		}
		if (!(dlog.isMember(z0))){
			throw new CheatAttemptException("z0 element is not a member of the current DlogGroup");
		}
		if (!(dlog.isMember(z1))){
			throw new CheatAttemptException("z1 element is not a member of the current DlogGroup");
		}
		
		if (z0.equals(z1)){
			throw new CheatAttemptException("z0 and z1 are equal");
		}
		
	}
	
	/**
	 * Runs the following line from the protocol:
	 * "SAMPLE random values u0,u1,v0,v1 in  {0, . . . , q-1} "
	 */
	private void sampleRandomValues() {
		
		
		//Save the random chosen values a s class members. 
		u0 = BigIntegers.createRandomInRange(BigInteger.ZERO, qMinusOne, random);
		u1 = BigIntegers.createRandomInRange(BigInteger.ZERO, qMinusOne, random);
		v0 = BigIntegers.createRandomInRange(BigInteger.ZERO, qMinusOne, random);
		v1 = BigIntegers.createRandomInRange(BigInteger.ZERO, qMinusOne, random);
	}
	
	/**
	 * Runs the following lines from the protocol:
	 * "COMPUTE:
	 *	•	w0 = x^u0 • g^v0
	 *	•	k0 = (z0)^u0 • y^v0
	 *	•	w1 = x^u1 • g^v1
	 *	•	k1 = (z1)^u1 • y^v1
	 * 
	 */
	private void computePreProcessValues() {
		GroupElement g = dlog.getGenerator(); //Get the group generator.
		
		//Calculates w0 = x^u0 • g^v0
		w0 = dlog.multiplyGroupElements(dlog.exponentiate(x, u0), dlog.exponentiate(g, v0));
		//Calculates k0 = (z0)^u0 • y^v0
		k0 = dlog.multiplyGroupElements(dlog.exponentiate(z0, u0), dlog.exponentiate(y, v0));
		
		//Calculates w1 = x^u1 • g^v1
		w1 = dlog.multiplyGroupElements(dlog.exponentiate(x, u1), dlog.exponentiate(g, v1));
		//Calculates k1 = (z1)^u1 • y^v1
		k1 = dlog.multiplyGroupElements(dlog.exponentiate(z1, u1), dlog.exponentiate(y, v1));
		
	}
	
	/**
	 * Runs the following lines from the protocol:
	 * "COMPUTE: in byteArray scenario:
	 *	•	c0 = x0 XOR KDF(|x0|,k0)
	 *	•	c1 = x1 XOR KDF(|x1|,k1) 
	 *	OR in GroupElement scenario:
	 *	•	c0 = x0 * k0
	 *	•	c1 = x1 * k1"
	 * @return tuple contains (w0, c0, w1, c1) to send to the receiver.
	 */
	protected abstract OTSMessage computeTuple();
		
	/**
	 * Runs the following lines from the protocol:
	 * "SEND (w0, c0) and (w1, c1) to R"
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
