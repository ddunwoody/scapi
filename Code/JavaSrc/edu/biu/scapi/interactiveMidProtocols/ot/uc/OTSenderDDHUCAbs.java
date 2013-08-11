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
import edu.biu.scapi.interactiveMidProtocols.ot.OTRMessage;
import edu.biu.scapi.interactiveMidProtocols.ot.OTSMessage;
import edu.biu.scapi.interactiveMidProtocols.ot.OTSender;
import edu.biu.scapi.interactiveMidProtocols.ot.OTUtil;
import edu.biu.scapi.interactiveMidProtocols.ot.OTUtil.RandOutput;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.dlog.cryptopp.CryptoPpDlogZpSafePrime;
import edu.biu.scapi.primitives.dlog.miracl.MiraclDlogECF2m;
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
public abstract class OTSenderDDHUCAbs implements OTSender, UC{

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

	private Channel channel;
	protected DlogGroup dlog;
	private SecureRandom random;
	private GroupElement g0, g1, h0, h1;

	//Values required for the tuple calculation:
	protected GroupElement u0, v0, u1, v1;

	/**
	 * Constructor that sets the given channel and choose default values to the other parameters.
	 * @param channel
	 */
	public OTSenderDDHUCAbs(Channel channel){
		
		
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
	 * @throws SecurityLevelException if the given dlog is not DDH secure
	 */
	public OTSenderDDHUCAbs(Channel channel, DlogGroup dlog, GroupElement g0, GroupElement g1, 
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
		this.g0 = g0;
		this.g1 = g1;
		this.h0 = h0;
		this.h1 = h1;
	}

	/**
	 * Runs the part of the protocol where the sender input is not yet necessary as follows:
	 * "WAIT for message (g,h) from R
	 *	COMPUTE (u0,v0) = RAND(g0,g,h0,h)
	 *	COMPUTE (u1,v1) = RAND(g1,g,h1,h)".
	 * @throws IOException if failed to receive a message.
	 * @throws ClassNotFoundException 
	 */
	public void preProcess() throws ClassNotFoundException, IOException{
		//Wait for message (g,h) from R
		OTRMessage message = waitForMessageFromReceiver();
		GroupElement g = dlog.reconstructElement(true, message.getFirstGE());
		GroupElement h = dlog.reconstructElement(true, message.getSecondGE());
		
		//Compute (u0,v0) = RAND(g0,g,h0,h)
		//Compute (u1,v1) = RAND(g1,g,h1,h)
		RandOutput tuple0 = OTUtil.rand(dlog, g0, g, h0, h, random);
		RandOutput tuple1 = OTUtil.rand(dlog, g1, g, h1, h, random);
		u0 = tuple0.getU();
		v0 = tuple0.getV();
		u1 = tuple1.getU();
		v1 = tuple1.getV();
	}

	/**
	 * Runs the part of the protocol where the sender's input is necessary as follows:<p>
	 *		COMPUTE:<p> 
	 *			in the byte array scenario<p>
	 *				•   c0 = x0 XOR KDF(|x0|,v0)
	 *				•   c1 = x1 XOR KDF(|x1|,v1)
	 *			OR in the GroupElement scenario:<p>
	 *				•	c0 = x0 * v0<p>
	 *				•	c1 = x1 * v1<p>
	 *		SEND (u0,c0) and (u1,c1) to R<p>
	 *		OUTPUT nothing<p>
	 * @throws IOException if failed to send the message.
	 * @throws NullPointerException if the function {@link #preProcess()} has not been called at least once
	 */
	public void transfer() throws IOException, NullPointerException{
		//This function can be called only after preProcess() function has been called at least once. 
		//The caller application can choose to call preProcess for every new OT it needs to perform or to use the pre-processed values 
		//calculated the first time for all or many upcoming transfers. It depends on the application's needs.
		//In any case, we could check here if the necessary pre-processed values are null and if so not to transfer but since in most cases the values will not be null(assuming the user of the functionality
		//understands what she is doing) it is enough to catch the NullPointerException and throw instead of it a IllegalStateException with an explanation.
		try{
			OTSMessage message = computeTuple();
			sendTupleToReceiver(message);
		}catch(NullPointerException e){
			throw new IllegalStateException("preProcess function should be called before transfer at least once");
		}

	}

	/**
	 * Runs the following line from the protocol:
	 * "WAIT for message (h0,h1) from R"
	 * @return the received message.
	 * @throws ClassNotFoundException 
	 * @throws IOException if failed to receive a message.
	 */
	private OTRMessage waitForMessageFromReceiver() throws ClassNotFoundException, IOException{
		Serializable message = null;
		try {
			message = channel.receive();
		} catch (IOException e) {
			throw new IOException("Failed to receive message. The thrown message is: " + e.getMessage());
		}
		if (!(message instanceof OTRMessage)){
			throw new IllegalArgumentException("The received message should be an instance of OTSMessage");
		}
		return (OTRMessage) message;
	}

	/**
	 * Runs the following lines from the protocol:
	 * "COMPUTE: in the byte array scenario:
	 *			•   c0 = x0 XOR KDF(|x0|,v0)
	 *			•   c1 = x1 XOR KDF(|x1|,v1)
	 *		OR in the GroupElement scenario:<p>
	 *			•	c0 = x0 * v0<p>
	 *			•	c1 = x1 * v1<p>
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
