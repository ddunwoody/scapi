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
import java.security.SecureRandom;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.SecurityLevelException;
import edu.biu.scapi.interactiveMidProtocols.ot.OTSInput;
import edu.biu.scapi.interactiveMidProtocols.ot.OTSender;
import edu.biu.scapi.interactiveMidProtocols.ot.fullSimulation.OTFullSimOnGroupElementSenderTransferUtil;
import edu.biu.scapi.interactiveMidProtocols.ot.fullSimulation.OTFullSimPreprocessPhaseValues;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.securityLevel.DDH;
import edu.biu.scapi.securityLevel.Malicious;
import edu.biu.scapi.securityLevel.UC;

/**
 * Concrete class for OT sender based on the DDH assumption that achieves UC security in
 * the common reference string model.
 * This is implementation in GroupElement mode.
 * 
 * This class derived from OTUCDDHSenderAbs and implements the functionality 
 * related to the byte array inputs.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class OTUCDDHOnGroupElementSender implements OTSender, Malicious, UC{
	
	protected DlogGroup dlog;
	private SecureRandom random;
	private GroupElement g0, g1, h0, h1; //Common reference string
	
	/**
	 * Constructor that sets the given common reference string composed of a DLOG 
	 * description (G,q,g0) and (g0,g1,h0,h1) which is a randomly chosen non-DDH tuple, 
	 * kdf and random.
	 * @param dlog must be DDH secure.
	 * @param g0 
	 * @param g1 
	 * @param h0 
	 * @param h1 
	 * @param kdf
	 * @param random
	 * @throws SecurityLevelException if the given DlogGroup is not DDH secure.
	 */
	public OTUCDDHOnGroupElementSender(DlogGroup dlog, GroupElement g0, 
			GroupElement g1, GroupElement h0, GroupElement h1, SecureRandom random) throws SecurityLevelException{
		//The underlying dlog group must be DDH secure.
		if (!(dlog instanceof DDH)){
			throw new SecurityLevelException("DlogGroup should have DDH security level");
		}
		
		this.dlog = dlog;
		this.random = random;
		this.g0 = g0;
		this.g1 = g1;
		this.h0 = h0;
		this.h1 = h1;
		
		// This protocol has no pre process stage.
	}
	
	/**
	 * Runs the part of the protocol where the sender's input is necessary as follows:<p>
	 *	WAIT for message (g,h) from R
	 *	COMPUTE (u0,v0) = RAND(g0,g,h0,h)
	 *	COMPUTE (u1,v1) = RAND(g1,g,h1,h)		
	 *	COMPUTE:<p> 
	 *		•	c0 = x0 * v0<p>
	 *		•	c1 = x1 * v1<p>
	 *	SEND (u0,c0) and (u1,c1) to R<p>
	 *	OUTPUT nothing<p>
	 * The transfer stage of OT protocol which can be called several times in parallel.
	 * In order to enable the parallel calls, each transfer call should use a different channel to send and receive messages.
	 * This way the parallel executions of the function will not block each other.
	 * The parameters given in the input must match the DlogGroup member of this class, which given in the constructor.
	 * @param channel 
	 * @param input
	 * @throws IOException if failed to send the message.
	 * @throws ClassNotFoundException 
	 */
	public void transfer(Channel channel, OTSInput input) throws IOException, NullPointerException, ClassNotFoundException{
		//Creates the utility class that executes the transfer phase.
		OTFullSimOnGroupElementSenderTransferUtil transferUtil = new OTFullSimOnGroupElementSenderTransferUtil(dlog, random);
		transferUtil.transfer(channel, input, new OTFullSimPreprocessPhaseValues(g0, g1, h0, h1));
	}

}
