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
 * This interface is used by the committer to prove that:<p>
 * 1. The committer knows the committed value.<p>
 * 2. The committed value was x.<p>
 * 
 * All commitment scheme that have proofs should implement this interface.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public interface CmtWithProofsCommitter extends CmtCommitter{

	/**
	 * Proves that the committer knows the committed value.
	 * @param id of the commitment message.
	 * @throws ClassNotFoundException if the commitment cannot be serialized
	 * @throws CheatAttemptException if the committer suspects that the receiver attempted cheating
	 * @throws IOException if there is any problem at the communication level
	 */
	public void proveKnowledge(long id) throws IOException, CheatAttemptException, ClassNotFoundException;
	
	/**
	 * Proves that the committed value with the given id was x.
	 * @param id of the committed value.
	 * @throws CommitValueException if the commit value does not match the implementing commitment
	 * @throws ClassNotFoundException if the commitment cannot be serialized
	 * @throws CheatAttemptException if the committer suspects that the receiver attempted cheating
	 * @throws IOException if there is any problem at the communication level
	 */
	public void proveCommittedValue(long id) throws IOException, CheatAttemptException, ClassNotFoundException, CommitValueException;
}
