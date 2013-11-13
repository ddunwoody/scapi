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
package edu.biu.scapi.interactiveMidProtocols.ot;

import java.io.IOException;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.exceptions.InvalidDlogGroupException;

/**
 * General interface. Every class that implements it is signed as Oblivious Transfer sender.<p>
 * 
 * Oblivious Transfer is the situation where a sender has n messages, and the receiver has an 
 * index i. The receiver wishes to receive the i-th among the sender's messages, 
 * without the sender learning i, while the sender wants to ensure that the receiver receive 
 * only one of the n messages.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public interface OTSender {
	
	// Some OT protocols have a pre-process stage before the transfer. 
	// Usually, pre process is done once at the beginning of the protocol and will not be executed later, 
	// then the transfer function could be called multiple times.
	// We implement the pre process stage at construction time. 
	// A protocol that needs to call pre process after the construction time, should create a new instance.
	
	/**
	 * The transfer stage of OT protocol which can be called several times in parallel.<p>
	 * The OT implementation support usage of many calls to transfer, with single preprocess execution. <p>
	 * This way, one can execute batch OT by creating the OT sender once and call the transfer function for each input couple.<p>
	 * In order to enable the parallel calls, each transfer call should use a different channel to send and receive messages.
	 * This way the parallel executions of the function will not block each other.
	 * @param channel each call should get a different one.
	 * @param input The parameters given in the input must match the DlogGroup member of this class, which given in the constructor.
	 * @throws IOException if there was a problem during the communication.
	 * @throws ClassNotFoundException if there was a problem in the serialization mechanism.
	 * @throws CheatAttemptException if the sender suspects that the receiver is trying to cheat.
	 * @throws InvalidDlogGroupException if the given DlogGRoup is not valid.
	 */
	public void transfer(Channel channel, OTSInput input) throws IOException, ClassNotFoundException, CheatAttemptException, InvalidDlogGroupException;
}
