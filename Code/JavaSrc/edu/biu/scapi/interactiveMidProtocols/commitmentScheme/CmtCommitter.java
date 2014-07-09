/**
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
Copyright (c) 2012 - SCAPI (http://crypto.biu.ac.il/scapi)
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
 * This the general interface of the Committer side of a Commitment Scheme. A commitment scheme has a commitment phase in which the committer send the commitment to
 * the Receiver; and a decommitment phase in which the the Committer sends the decommitment to the Receiver.  
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public interface CmtCommitter {

	/**
	 * Generate a commitment message using the given input and ID.<p>
	 * There are cases when the user wants to commit on the input but remain non-interactive, 
	 * meaning not to send the generate message yet. 
	 * The reasons for doing that are vary, for example the user wants to prepare a lot of commitments and send together.
	 * In these cases the commit function is not useful since it sends the generates commit message to the other party. <p>
	 * This function generates the message without sending it and this allows the user to save it and send it later if he wants.<p>
	 * In case the commit phase is interactive, the commit message cannot be generated and an IllegalStateException will be thrown. 
	 * In this case one should use the commit function instead.
	 * 
	 * Code example: giving a committer object and an input,
	 * 
	 * //Create three commitment messages.
	 * CmtCCommitmentMsg msg1 = generateCommitmentMsg(input, 1);
	 * CmtCCommitmentMsg msg2 = generateCommitmentMsg(input, 2);
	 * CmtCCommitmentMsg msg3 = generateCommitmentMsg(input, 3);
	 * ...
	 * 
	 * try {
	 *		//Send the messages by the channel.
	 *		channel.send(msg1);
	 *		channel.send(msg2);
	 *		channel.send(msg3);
	 *	} catch (IOException e) {
	 *		//Should remove the failed commitment from the commitmentMap!
	 *		throw new IOException("failed to send the commitment. The error is: " + e.getMessage());
	 *	}	
	 * 
	 * @param input The value that the committer commits about.
	 * @param id Unique value attached to the input to keep track of the commitments in the case that many commitments are performed one after the other without decommiting them yet. 
	 * @return the generated commitment object.
	 * @throws IllegalStateException In case the commit phase is interactive.
	 */
	public CmtCCommitmentMsg generateCommitmentMsg(CmtCommitValue input, long id);

	/**
	 * This function is the heart of the commitment phase from the Committer's point of view.
	 * @param input The value that the committer commits about.
	 * @param id Unique value attached to the input to keep track of the commitments in the case that many commitments are performed one after the other without decommiting them yet. 
	 * @throws IOException if there is any problem at the communication level
	 */
	public void commit(CmtCommitValue input, long id) throws IOException;

	/**
	 * Generate a decommitment message using the given id.<p>
	 * 
	 * There are cases when the user wants to decommit but remain non-interactive, meaning not to send the generate message yet. 
	 * The reasons for doing that are vary, for example the user wants to prepare a lot of decommitments and send together.
	 * In these cases the decommit function is not useful since it sends the generates decommit message to the other party. <p>
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
	 * @param id Unique value attached to the input to keep track of the commitments in the case that many commitments are performed one after the other without decommiting them yet. 
	 * @return the generated decommitment object.
	 * @throws IllegalStateException In case the decommit phase is interactive.
	 */
	public CmtCDecommitmentMessage generateDecommitmentMsg(long id);
	
	/**
	 * This function is the heart of the decommitment phase from the Committer's point of view.
	 * @param id Unique value used to identify which previously committed value needs to be decommitted now.
	 * @throws IOException if there is any problem at the communication level
	 * @throws CheatAttemptException if the committer suspects that the receiver attempted cheating
	 * @throws ClassNotFoundException if the commitment cannot be serialized
	 * @throws CommitValueException if the commit value does not match the implementing commitment.
	 */
	public void decommit(long id) throws IOException, CheatAttemptException, ClassNotFoundException, CommitValueException;
	
	/**
	 * This function samples random commit value to commit on.
	 * @return the sampled commit value.
	 */
	public CmtCommitValue sampleRandomCommitValue();
	
	/**
	 * This function wraps the raw data x with a suitable CommitValue instance according to the actual implementaion.
	 * @param x array to convert into a commitValue.
	 * @return the created CommitValue.
	 * @throws CommitValueException if the commit value does not match the implementing commitment
	 */
	public CmtCommitValue generateCommitValue(byte[] x) throws CommitValueException;
	
	/**
	 * This function converts the given commit value to a byte array. 
	 * @param value to get its bytes.
	 * @return the generated bytes.
	 */
	public byte[] generateBytesFromCommitValue(CmtCommitValue value);
	
	/**
	 * This function returns the values calculated during the preprocess phase.<p>
	 * This function is used for protocols that need values of the commitment, 
	 * like ZK protocols during proofs on the commitment.
	 * We recommended not to call this function from somewhere else.
	 * @return values calculated during the preprocess phase
	 */
	public Object[] getPreProcessValues();
	
	/**
	 * This function returns the values calculated during the commit phase for a specific commitment.<p>
	 * This function is used for protocols that need values of the commitment, 
	 * like ZK protocols during proofs on the commitment.
	 * We recommended not to call this function from somewhere else.
	 * @param id of the specific commitment
	 * @return values calculated during the commit phase
	 */
	public CmtCommitmentPhaseValues getCommitmentPhaseValues(long id);
	
}