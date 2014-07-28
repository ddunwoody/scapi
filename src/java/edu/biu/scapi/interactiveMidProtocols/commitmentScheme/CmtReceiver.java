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
package edu.biu.scapi.interactiveMidProtocols.commitmentScheme;

import java.io.IOException;

import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.exceptions.CommitValueException;

/**
 * This the general interface of the Receiver side of a Commitment Scheme. A commitment scheme has a commitment phase in which the Receiver waits for the commitment
 * sent by the Committer; and a decommitment phase in which the Receiver waits for the decommitment sent by the Committer and checks whether to accept or reject the decommitment.  
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public interface CmtReceiver {

	/**
	 * This function is the heart of the commitment phase from the Receiver's point of view. 
	 * @return the id of the commitment and some other information if necessary according to the implementing class. 
	 * @throws ClassNotFoundException if the commitment received cannot be deserialized
	 * @throws IOException if there is any problem at the communication level
	 */
	public CmtRCommitPhaseOutput receiveCommitment() throws ClassNotFoundException, IOException;

	/**
	 * This function is the heart of the decommitment phase from the Receiver's point of view.
	 * @param id wait for a specific message according to this id
	 * @return the commitment
	 * @throws ClassNotFoundException if the decommitment received cannot be deserialized
	 * @throws IOException if there is any problem at the communication level.
	 * @throws CommitValueException if the commit value does not match the implementing commitment.
	 * @throws CheatAttemptException if there is an error that could have been caused by a cheating attempt
	 */
	public CmtCommitValue receiveDecommitment(long id) throws ClassNotFoundException, IOException, CommitValueException, CheatAttemptException;
	
	/**
	 * Verifies the given decommitment object according to the given commitment object.<p>
	 * 
	 * There are cases when the committer sends the commitment and decommitments in the application, and the receiver does not use the receiveCommitment and receiveDecommitment function. 
	 * In these cases this function should be called for each pair of commitment and decommitment messages.
	 * The reasons for doing that are vary, for example a protocol that prepare a lot of commitments and send together.
	 * In these cases the receiveCommitment and receiveDecommitment functions are not useful since it receives the generates messages separately. to the other party. <p>
	 * This function generates the message without sending it and this allows the user to save it and send it later if he wants.<p>
	 * In case the decommit phase is interactive, the decommit message cannot be generated and an IllegalStateException will be thrown. 
	 * In this case one should use the decommit function instead.
	 * 
	 * Code example: giving a committer object and an input,
	 * 
	 * //Create three commitment messages.
	 * CmtCDecommitmentMessage msg1 = generateDecommitmentMsg(1);
	 * CmtCDecommitmentMessage msg2 = generateDecommitmentMsg(2);
	 * CmtCDecommitmentMessage msg3 = generateDecommitmentMsg(3);
	 * ...
	 * 
	 * try {
	 *		//Send the messages by the channel.
	 *		channel.send(msg1);
	 *		channel.send(msg2);
	 *		channel.send(msg3);
	 *	} catch (IOException e) {
	 *		throw new IOException("failed to send the decommitment. The error is: " + e.getMessage());
	 *	}	
	 *
	 * @param commitmentMsg the commitment object.
	 * @param decommitmentMsg the decommitment object
	 * @return the committed value if the decommit succeeded; null, otherwise.
	 */
	public CmtCommitValue verifyDecommitment(CmtCCommitmentMsg commitmentMsg, CmtCDecommitmentMessage decommitmentMsg);
	
	/**
	 * Return the values used during the pre-process phase (usually upon construction). Since these values vary between the different implementations this function
	 * returns a general array of Objects.
	 * @return a general array of Objects
	 */
	public Object[] getPreProcessedValues();
	
	/**
	 * Return the intermediate values used during the commitment phase.
	 * @param id get the commitment values according to this id.
	 * @return a general array of Objects.
	 */
	public Object getCommitmentPhaseValues(long id);
	
	/**
	 * This function converts the given commit value to a byte array. 
	 * @param value to get its bytes.
	 * @return the generated bytes.
	 */
	public byte[] generateBytesFromCommitValue(CmtCommitValue value);
}