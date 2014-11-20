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
import java.util.logging.Level;

import edu.biu.scapi.generals.Logging;
import org.bouncycastle.util.BigIntegers;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.exceptions.SecurityLevelException;
import edu.biu.scapi.generals.ScapiDefaultConfiguration;
import edu.biu.scapi.interactiveMidProtocols.ot.OTRGroupElementPairMsg;
import edu.biu.scapi.interactiveMidProtocols.ot.OTSInput;
import edu.biu.scapi.interactiveMidProtocols.ot.OTSMsg;
import edu.biu.scapi.interactiveMidProtocols.ot.OTSender;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.securityLevel.DDH;
import edu.biu.scapi.tools.Factories.DlogGroupFactory;

/**
 * Abstract class for Semi-Honest OT assuming DDH sender. <p>
 * Semi-Honest OT has two modes: one is on ByteArray and the second is on GroupElement.
 * The difference is in the input and output types and the way to process them. <p>
 * In spite that, there is a common behavior for both modes which this class implements.<p>
 * 
 * The pseudo code of this protocol can be found in Protocol 4.1 of pseudo codes document at {@link http://crypto.biu.ac.il/scapi/SDK_Pseudocode_SCAPI_V2.0.0.pdf}.<p>
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
abstract class OTSemiHonestDDHSenderAbs implements OTSender{

	/*	
	  This class runs the following protocol:
		 	WAIT for message (h0,h1) from R
			SAMPLE a random value r in  [0, . . . , q-1] 
			COMPUTE:
				*	u = g^r
				*	k0 = h0^r
				*	v0 = x0 XOR KDF(|x0|,k0) - in byteArray scenario.
						OR x0*k0			 - in GroupElement scenario.
				*	k1 = h1^r
				*	v1 = x1 XOR KDF(|x1|,k1) - in byteArray scenario.
						OR x1*k1 			 - in GroupElement scenario.
			SEND (u,v0,v1) to R
			OUTPUT nothing
	 */	 

	protected DlogGroup dlog;
	private SecureRandom random;
	private BigInteger qMinusOne;

	/**
	 * Constructor that chooses default values of DlogGroup and SecureRandom.
	 */
	OTSemiHonestDDHSenderAbs() {
		//Read the default DlogGroup name from a configuration file.
		String dlogName = ScapiDefaultConfiguration.getInstance().getProperty("DDHDlogGroup");
		DlogGroup dlog = null;
		try {
			//Create the default DlogGroup by the factory.
			dlog = DlogGroupFactory.getInstance().getObject(dlogName);
            Logging.getLogger().log(Level.FINE, dlog.getGroupType());
		} catch (FactoriesException e1) {
			// Should not occur since the dlog name in the configuration file is valid.
		}
		
		try {
			doConstruct(dlog, new SecureRandom());
		} catch (SecurityLevelException e1) {
			// Should not occur since the dlog in the configuration file is as secure as needed.
		}
	}

	/**
	 * Constructor that sets the given dlogGroup and random.
	 * @param dlog must be DDH secure.
	 * @param random
	 * @throws SecurityLevelException if the given dlog is not DDH secure
	 */
	OTSemiHonestDDHSenderAbs(DlogGroup dlog, SecureRandom random) throws SecurityLevelException{

		doConstruct(dlog, random);
	}

	/**
	 * Sets the given members.
	 * @param dlog must be DDH secure.
	 * @param random
	 * @throws SecurityLevelException if the given dlog is not DDH secure.
	 */
	private void doConstruct(DlogGroup dlog, SecureRandom random) throws SecurityLevelException {
		//The underlying dlog group must be DDH secure.
		if (!(dlog instanceof DDH)){
			throw new SecurityLevelException("DlogGroup should have DDH security level");
		}

		this.dlog = dlog;
		this.random = random;
		qMinusOne =  dlog.getOrder().subtract(BigInteger.ONE);

		// This protocol has no pre process stage.
	}

	/**
	 * Runs the transfer phase of the OT protocol.<p>
	 * This is the phase where the input is necessary as follows:<p>
	 *	"WAIT for message (h0,h1) from R<p>
	 *	SAMPLE a random value r in  [0, . . . , q-1] <p>
	 *	COMPUTE:<p>
	 *		*	u = g^r<p>
	 *		*	k0 = h0^r<p>
	 *		*	k1 = h1^r<p>
	 *	COMPUTE:<p>
	 *			in the byte array scenario<p>
	 *				*	v0 = x0 XOR KDF(|x0|,k0)<p> 
	 *				*	v1 = x1 XOR KDF(|x1|,k1)<p> 
	 *			OR in the GroupElement scenario:<p>
	 *				*	v0 = x0 * k0<p>
	 *				*	v1 = x1 * k1"<p>
	 *		SEND (u,v0,v1) to R<p>
	 *		OUTPUT nothing"<p>
	 */
	public void transfer(Channel channel, OTSInput input) throws IOException, ClassNotFoundException{
		
		//WAIT for message (h0,h1) from R
		OTRGroupElementPairMsg message = waitForMessageFromReceiver(channel);
		
		//SAMPLE a random value r in  [0, . . . , q-1] 
		BigInteger r = BigIntegers.createRandomInRange(BigInteger.ZERO, qMinusOne, random);
		
		//Compute u, k0, k1
		GroupElement u = computeU(r);
		GroupElement k0 = computeK0(r, message);
		GroupElement k1 = computeK1(r, message);
		
		OTSMsg messageToSend = computeTuple(input, u, k0, k1);
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
	 * Runs the following line from the protocol:
	 * "COMPUTE u = g^r"
	 * @param r the exponent
	 * @return the computed u.
	 */
	private GroupElement computeU(BigInteger r) {
		GroupElement g = dlog.getGenerator(); //Get the group generator.

		//Calculate u = g^r.
		return dlog.exponentiate(g, r);
	}
	
	/**
	 * Runs the following line from the protocol:
	 * "COMPUTE k0 = h0^r"
	 * @param r the exponent
	 * @param message contains h0
	 * @return the computed k0
	 */
	private GroupElement computeK0(BigInteger r, OTRGroupElementPairMsg message) {

		//Recreate h0 from the data in the received message.
		GroupElement h0 = dlog.reconstructElement(true, message.getFirstGE());
		
		//Calculate k0 = h0^r.
		return dlog.exponentiate(h0, r);
	}
	
	/**
	 * Runs the following line from the protocol:
	 * "COMPUTE k1 = h1^r"
	 * @param r the exponent
	 * @param message contains h1
	 * @return the computed k1
	 */
	private GroupElement computeK1(BigInteger r, OTRGroupElementPairMsg message) {
		
		//Recreate h0, h1 from the data in the received message.
		GroupElement h1 = dlog.reconstructElement(true, message.getSecondGE());

		//Calculate k1 = h1^r.
		return dlog.exponentiate(h1, r);
	}

	/**
	 * Runs the following lines from the protocol:
	 * "COMPUTE: in the byte array scenario:
	 *		*	v0 = x0 XOR KDF(|x0|,k0) 
	 *		*	v1 = x1 XOR KDF(|x1|,k1)
	 * OR in the GroupElement scenario:
	 * 		*	v0 = x0 * k0
	 *		*	v1 = x1 * k1"
	 * @param input
	 * @param k1 
	 * @param k0 
	 * @param u 
	 * @return tuple contains (u, v0, v1) to send to the receiver.
	 */
	protected abstract OTSMsg computeTuple(OTSInput input, GroupElement u, GroupElement k0, GroupElement k1);

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
