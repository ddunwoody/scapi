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
package edu.biu.scapi.interactiveMidProtocols.ot.otBatch.semiHonest;

import java.io.IOException;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.logging.Level;

import edu.biu.scapi.generals.Logging;
import org.bouncycastle.util.BigIntegers;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.exceptions.SecurityLevelException;
import edu.biu.scapi.generals.ScapiDefaultConfiguration;
import edu.biu.scapi.interactiveMidProtocols.ot.OTRGroupElementPairMsg;
import edu.biu.scapi.interactiveMidProtocols.ot.OTSMsg;
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.OTBatchSInput;
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.OTBatchSOutput;
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.OTBatchSender;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.securityLevel.DDH;
import edu.biu.scapi.tools.Factories.DlogGroupFactory;

/**
 * Abstract class for batch Semi-Honest OT assuming DDH sender.<p>
 * Batch Semi-Honest OT has two modes: one is on ByteArray and the second is on GroupElement.
 * The difference is in the input and output types and the way to process them. 
 * In spite that, there is a common behavior for both modes which this class implements.<p>
 * 
 * The pseudo code of this protocol can be found in Protocol 5.1 of pseudo codes document at {@link http://crypto.biu.ac.il/scapi/SDK_Pseudocode_SCAPI_V2.0.0.pdf}.<p>
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
abstract class OTSemiHonestDDHBatchSenderAbs implements OTBatchSender{

	/*	
	  This class runs the following protocol:
		 	WAIT for message (h0i,h1i) from R
			SAMPLE a single random value r <-  {0, . . . , q-1} and COMPUTE u=g^r
			For every i=1,...,m, COMPUTE:
			*	ki0 = (hi0)^r
			*	ki1 = (hi1)^r
			In the byte array scenario:
			*	vi0 = xi0 XOR KDF(|xi0|,ki0)
			*	vi1 = xi1 XOR KDF(|xi1|,ki1)
			In the group element scenario:
			*   vi0 = xi0 * ki0
			*	vi1 = xi1 * ki1
			For every i=1,...,m, SEND (u,vi0,vi1) to R
			OUTPUT nothing

	 */	 

	protected DlogGroup dlog;
	private SecureRandom random;
	private BigInteger qMinusOne;

	/**
	 * Constructor that chooses default values of DlogGroup and SecureRandom.
	 */
	OTSemiHonestDDHBatchSenderAbs() {
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
	OTSemiHonestDDHBatchSenderAbs(DlogGroup dlog, SecureRandom random) throws SecurityLevelException{

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
	 * Runs the transfer phase of the protocol.<p>
	 *	"WAIT for message (h0i,h1i) from R<p>
	 *	SAMPLE a single random value r <-  {0, . . . , q-1} and COMPUTE u=g^r<p>
	 *	For every i=1,...,m, COMPUTE:<p>
	 *		*	ki0 = (hi0)^r<p>
	 *		*	ki1 = (hi1)^r<p>
	 *		In the byte array scenario:<p>
	 *		*	vi0 = xi0 XOR KDF(|xi0|,ki0)<p>
	 *		*	vi1 = xi1 XOR KDF(|xi1|,ki1)<p>
	 *		In the group element scenario:<p>
	 *		*   vi0 = xi0 * ki0<p>
	 *		*	vi1 = xi1 * ki1<p>
	 *	For every i=1,...,m, SEND (u,vi0,vi1) to R<p>
	 *	OUTPUT nothing"<p>
	 * @return null, this protocol has no output.
	 */
	public OTBatchSOutput transfer(Channel channel, OTBatchSInput input) throws ClassNotFoundException, IOException {
		//WAIT for message (hi0,hi1) from R
		OTRGroupElementBatchMsg message = waitForMessageFromReceiver(channel);
		
		//SAMPLE a random value r in  [0, . . . , q-1] 
		BigInteger r = BigIntegers.createRandomInRange(BigInteger.ZERO, qMinusOne, random);
		GroupElement g = dlog.getGenerator(); //Get the group generator.
		
		//Calculate u = g^r.
		GroupElement u = dlog.exponentiate(g, r);
		
		ArrayList<OTRGroupElementPairMsg> tuples = message.getTuples();
		int size = tuples.size();
		ArrayList<GroupElement> k0Array = new ArrayList<GroupElement>();
		ArrayList<GroupElement> k1Array = new ArrayList<GroupElement>();
		GroupElement h0, h1;
		OTRGroupElementPairMsg tuple;
		
		//For every i=1,...,m, COMPUTE:
		//	ki0 = (hi0)^r
		//	ki1 = (hi1)^r
		for (int i=0; i<size; i++){
			tuple = tuples.get(i);
			//Recreate h0 from the data in the received message.
			h0 = dlog.reconstructElement(true, tuple.getFirstGE());
			h1 = dlog.reconstructElement(true, tuple.getSecondGE());
			
			//Calculate k0 = h0^r.
			k0Array.add(i, dlog.exponentiate(h0, r));
			k1Array.add(i, dlog.exponentiate(h1, r));
		}
		
		OTSMsg messageToSend = computeMsg(input, u, k0Array, k1Array);
		sendTupleToReceiver(channel, messageToSend);
		
		return null;//sould not return any data
	}

	/**
	 * Runs the following line from the protocol:
	 * "WAIT for message (h0,h1) from R"
	 * @param channel 
	 * @return the received message.
	 * @throws ClassNotFoundException 
	 * @throws IOException if failed to receive a message.
	 */
	private OTRGroupElementBatchMsg waitForMessageFromReceiver(Channel channel) throws ClassNotFoundException, IOException{
		Serializable message = null;
		try {
			message = channel.receive();
		} catch (IOException e) {
			throw new IOException("Failed to receive message. The thrown message is: " + e.getMessage());
		}
		if (!(message instanceof OTRGroupElementBatchMsg)){
			throw new IllegalArgumentException("The received message should be an instance of OTRGroupElementBatchMsg");
		}
		return (OTRGroupElementBatchMsg) message;
	}

	/**
	 * Runs the following lines from the protocol:
	 * "In the byte array scenario:
	 *	*	vi0 = xi0 XOR KDF(|xi0|,ki0)
	 *	*	vi1 = xi1 XOR KDF(|xi1|,ki1)
	 *	In the group element scenario:
	 *	*   vi0 = xi0 * ki0
	 *	*	vi1 = xi1 * ki1"
	 * @param input
	 * @param k1Array
	 * @param k0Array
	 * @param u 
	 * @return tuple contains (u, v0, v1) to send to the receiver.
	 */
	protected abstract OTSMsg computeMsg(OTBatchSInput input, GroupElement u, ArrayList<GroupElement> k0Array, ArrayList<GroupElement> k1Array);

	/**
	 * Runs the following lines from the protocol:
	 * "For every i=1,...,m, SEND (u,vi0,vi1) to R"
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
