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

import org.bouncycastle.util.BigIntegers;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.exceptions.SecurityLevelException;
import edu.biu.scapi.generals.ScapiDefaultConfiguration;
import edu.biu.scapi.interactiveMidProtocols.ot.OTRGroupElementPairMsg;
import edu.biu.scapi.interactiveMidProtocols.ot.OTSMsg;
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.OTBatchRInput;
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.OTBatchROutput;
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.OTBatchReceiver;
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.OTBatchRBasicInput;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.securityLevel.DDH;
import edu.biu.scapi.tools.Factories.DlogGroupFactory;

/**
 * Abstract class for batch Semi-Honest OT assuming DDH receiver.<p>
 * Batch Semi-Honest OT have two modes: one is on ByteArray and the second is on GroupElement.
 * The different is in the input and output types and the way to process them. <p>
 * 
 * In spite that, there is a common behavior for both modes which this class is implementing.<p>
 * 
 * The pseudo code of this protocol can be found in Protocol 5.1 of pseudo codes document at {@link http://crypto.biu.ac.il/scapi/SDK_Pseudocode_SCAPI_V2.0.0.pdf}.<p>
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
abstract class OTSemiHonestDDHBatchReceiverAbs implements OTBatchReceiver{
	/*	
	 	This class runs the following protocol:
		 	For every i=1,…m, SAMPLE random values alphaI <- Zq and hi <- G 
			For every i=1,...,m, COMPUTE hi0,hi1 as follows:
			1.	If SigmaI = 0 then hi0 = g^alphaI  and hi1=hi
			2.	If SigmaI = 1 then hi0=hi and hi1 = g^alphaI 
			For every i=1,...,m, SEND (hi0,hi1) to S
			In byte array scenario:
				For every i=1,...,m, COMPUTE kISigma = u^alphaI
				For every i=1,...,m, OUTPUT  xISigma = vISigma XOR KDF(|vISigma|,kISigma)
			In group element scenario:
				For every i=1,...,m, COMPUTE kISigma^(-1) = u^(-alphaI)
				For every i=1,...,m, OUTPUT  xISigma = vISigma  * (kISigma)^(-1)

	*/	
	
	protected DlogGroup dlog;
	private SecureRandom random;
	private BigInteger qMinusOne;
	
	/**
	 * Constructor that chooses default values of DlogGroup and SecureRandom.
	 */
	OTSemiHonestDDHBatchReceiverAbs(){
		//Read the default DlogGroup name from a configuration file.
		String dlogName = ScapiDefaultConfiguration.getInstance().getProperty("DDHDlogGroup");
		DlogGroup dlog = null;
		try {
			//Create the default DlogGroup by the factory.
			dlog = DlogGroupFactory.getInstance().getObject(dlogName);
			
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
	 * @throws SecurityLevelException if the given dlog is not DDH secure.
	 */
	OTSemiHonestDDHBatchReceiverAbs(DlogGroup dlog, SecureRandom random) throws SecurityLevelException{
		
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
	 * "For every i=1,…m, SAMPLE random values alphaI <- Zq and hi <- G <p>
	 *	For every i=1,...,m, COMPUTE hi0,hi1 as follows:<p>
	 *	1.	If SigmaI = 0 then hi0 = g^alphaI  and hi1=hi<p>
	 *	2.	If SigmaI = 1 then hi0=hi and hi1 = g^alphaI <p>
	 *	For every i=1,...,m, SEND (hi0,hi1) to S<p>
	 *	In byte array scenario:<p>
	 *		For every i=1,...,m, COMPUTE kISigma = u^alphaI<p>
	 *		For every i=1,...,m, OUTPUT  xISigma = vISigma XOR KDF(|vISigma|,kISigma)<p>
	 *	In group element scenario:<p>
	 *		For every i=1,...,m, COMPUTE kISigma^(-1) = u^(-alphaI)<p>
	 *		For every i=1,...,m, OUTPUT  xISigma = vISigma  * (kISigma)^(-1)"<p>
	 */
	public OTBatchROutput transfer(Channel channel, OTBatchRInput input) throws IOException, ClassNotFoundException{
		//check if the input is valid.
		//If input is not instance of OTRBasicInput, throw Exception.
		if (!(input instanceof OTBatchRBasicInput)){
			throw new IllegalArgumentException("input should be an instance of OTBatchRBasicInput");
		}
		
		ArrayList<Byte> sigmaArr = ((OTBatchRBasicInput) input).getSigmaArr();
		int size = sigmaArr.size();
		for (int i=0; i<size; i++){
			//The given sigmaI should be 0 or 1.
			if ((sigmaArr.get(i) != 0) && (sigmaArr.get(i)!= 1)){
				throw new IllegalArgumentException("Sigma should be 0 or 1");
			}
			
		}
		
		//For every i=1,…m, SAMPLE random values alphaI <- Zq.
		ArrayList<BigInteger> alphaArr = new ArrayList<BigInteger>();
		ArrayList<GroupElement> hArr = new ArrayList<GroupElement>();
		for (int i=0; i<size; i++){
			alphaArr.add(i, BigIntegers.createRandomInRange(BigInteger.ZERO, qMinusOne, random));
			hArr.add(i, dlog.createRandomElement());
		}
		
		//Compute h0, h1
		OTRGroupElementBatchMsg tuple = computeTuples(alphaArr, hArr, sigmaArr);
		
		//Send the tuple to sender
		sendTupleToSender(channel, tuple);
		
		//Wait for message from sender
		OTSMsg message = waitForMessageFromSender(channel);
		
		//Compute xSigma
		return computeFinalXSigma(sigmaArr, alphaArr, message);
	
	}
	
	/**
	 * Runs the following lines from the protocol:
	 *  "For every i=1,...,m, COMPUTE hi0,hi1 as follows:
	 *		1.	If SigmaI = 0 then hi0 = g^alphaI  and hi1=hi
	 *		2.	If SigmaI = 1 then hi0=hi and hi1 = g^alphaI "
	 * @param alpha random value sampled by the protocol
	 * @param sigma input for the protocol
	 * @return OTRSemiHonestMessage contains the tuple (h0, h1).
	 */
	private OTRGroupElementBatchMsg computeTuples(ArrayList<BigInteger> alphaArr, ArrayList<GroupElement> hArr, ArrayList<Byte> sigmaArr) {
		int size = alphaArr.size();
		GroupElement g = dlog.getGenerator();
		ArrayList<OTRGroupElementPairMsg> tuples = new ArrayList<OTRGroupElementPairMsg>();
		for (int i=0; i<size; i++){
			//Calculate g^alphaI.
			GroupElement gAlpha = dlog.exponentiate(g, alphaArr.get(i));
					
			GroupElement h0 = null;
			GroupElement h1 = null;
			//If SigmaI = 0 then hi0 = g^alphaI  and hi1=hi
			if (sigmaArr.get(i) == 0){
				h0 = gAlpha;
				h1 = hArr.get(i);
			} else{ //If SigmaI = 1 then hi0=hi and hi1 = g^alphaI
				h0 = hArr.get(i);
				h1 = gAlpha;
			}
			tuples.add(i, new OTRGroupElementPairMsg(h0.generateSendableData(), h1.generateSendableData()));
		}
		return new OTRGroupElementBatchMsg(tuples);
	}
	
	/**
	 * Runs the following line from the protocol:
	 * "For every i=1,...,m, SEND (hi0,hi1) to S"
	 * @param channel 
	 * @param tuple contains for every i=1,...,m,(h0,h1)
	 * @throws IOException if failed to send the message.
	 */
	private void sendTupleToSender(Channel channel, OTRGroupElementBatchMsg tuple) throws IOException {
		try {
			channel.send(tuple);
		} catch (IOException e) {
			throw new IOException("failed to send the message. The thrown message is: " + e.getMessage());
		}
		
	}
	
	/**
	 * Runs the following line from the protocol:
	 * "WAIT for the message (u, v0,v1) from S"
	 * @param channel 
	 * @return OTSMessage contains (u, v0,v1)
	 * @throws ClassNotFoundException
	 * @throws IOException if failed to receive a message.
	 */
	private OTSMsg waitForMessageFromSender(Channel channel) throws ClassNotFoundException, IOException {
		Serializable message;
		try {
			message = channel.receive();
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
	 * "COMPUTE in byte array scenario:
			For every i=1,...,m, COMPUTE kISigma = u^alphaI
			For every i=1,...,m, OUTPUT  xISigma = vISigma XOR KDF(|vISigma|,kISigma)
		COMPUTE in group element scenario:
			For every i=1,...,m, COMPUTE kISigma^(-1) = u^(-alphaI)
			For every i=1,...,m, OUTPUT  xISigma = vISigma  * (kISigma)^(-1)
	 * @param sigmaArr input for the protocol
	 * @param alphaArr random values sampled by the protocol
	 * @param message received from the sender
	 * @return OTROutput contains XSigma
	 */
	protected abstract OTBatchROutput computeFinalXSigma(ArrayList<Byte> sigma, ArrayList<BigInteger> alpha, OTSMsg message);

}
