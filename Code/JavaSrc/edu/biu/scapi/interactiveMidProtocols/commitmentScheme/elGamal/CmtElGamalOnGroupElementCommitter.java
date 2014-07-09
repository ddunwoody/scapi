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
package edu.biu.scapi.interactiveMidProtocols.commitmentScheme.elGamal;

import java.io.IOException;
import java.security.SecureRandom;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.CommitValueException;
import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.exceptions.InvalidDlogGroupException;
import edu.biu.scapi.exceptions.SecurityLevelException;
import edu.biu.scapi.generals.ScapiDefaultConfiguration;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCCommitmentMsg;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCommitter;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCommitValue;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtGroupElementCommitValue;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtOnGroupElement;
import edu.biu.scapi.midLayer.asymmetricCrypto.encryption.ScElGamalOnGroupElement;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.securityLevel.PerfectlyBindingCmt;
import edu.biu.scapi.tools.Factories.DlogGroupFactory;

/**
 * This class implements the committer side of the ElGamal commitment. <p>
 * It uses El Gamal encryption for  group elements, that is, the encryption class used is 
 * ScElGamalOnGroupElement. This default cannot be changed.<p>
 * 
 * The pseudo code of this protocol can be found in Protocol 3.4 of pseudo codes document at {@link http://crypto.biu.ac.il/scapi/SDK_Pseudocode_SCAPI_V2.0.0.pdf}.<p>
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class CmtElGamalOnGroupElementCommitter extends CmtElGamalCommitterCore implements CmtCommitter, PerfectlyBindingCmt, CmtOnGroupElement {
	 
	/**
	 * This constructor lets the caller pass the channel and the dlog group to work with. The El Gamal option (ScElGamalOnGroupElement)is set by default by the constructor and cannot be changed.
	 * @param channel used for the communication
	 * @param dlog	Dlog group
	 * @throws IllegalArgumentException
	 * @throws SecurityLevelException
	 * @throws InvalidDlogGroupException
	 * @throws IOException
	 */
	public CmtElGamalOnGroupElementCommitter(Channel channel, DlogGroup dlog, SecureRandom random) throws IllegalArgumentException, SecurityLevelException, InvalidDlogGroupException, IOException{
		super(channel, dlog, new ScElGamalOnGroupElement(dlog), random);
		
	}

	/**
	 * This constructor uses default Dlog group and El Gamal.
	 * @param channel
	 * @throws IOException
	 */
	public CmtElGamalOnGroupElementCommitter(Channel channel) throws IOException {
		String dlogGroupName = ScapiDefaultConfiguration.getInstance().getProperty("DDHDlogGroup");
		DlogGroup dlogGroup = null;
		//Create the Dlog group
		try {
			dlogGroup = DlogGroupFactory.getInstance().getObject(dlogGroupName);
		} catch (FactoriesException e1) {
			e1.printStackTrace();
		}
		//Proceed with construction of ElGamalCTCCore instance
		try {
			doConstruct(channel, dlogGroup, new ScElGamalOnGroupElement(dlogGroup), new SecureRandom());
		} catch (SecurityLevelException e) {
			e.printStackTrace();
		} catch (InvalidDlogGroupException e) {
			e.printStackTrace();
		}
		
	}
	
	public CmtCCommitmentMsg generateCommitmentMsg(CmtCommitValue input, long id){
		if (!(input instanceof CmtGroupElementCommitValue))
			throw new IllegalArgumentException("The input must be of type CmtGroupElementCommitValue");
		return super.generateCommitmentMsg(input, id);
	}

	/**
	 * Runs the commit phase of the commitment scheme.<p>
	 * Pseudo code:<p>
	 * "SAMPLE random values  r <- Zq<p>
	 *	COMPUTE u = g^r and v = h^r * x<p>
	 *	SEND c = (h,u,v) to R".<p>
	 */
	public void commit(CmtCommitValue input, long id) throws IOException {
		if (!(input instanceof CmtGroupElementCommitValue))
			throw new IllegalArgumentException("The input must be of type CmtGroupElementCommitValue");
		super.commit(input, id);	
	}
	
	/**
	 * This function samples random commit value and returns it.
	 * @return the sampled commit value
	 */
	public CmtCommitValue sampleRandomCommitValue(){
		return new CmtGroupElementCommitValue(dlog.createRandomElement());
	}
	
	@Override
	public CmtCommitValue generateCommitValue(byte[] x)throws CommitValueException {
		throw new CommitValueException("El Gamal committer cannot generate a CommitValue from a byte[], since there isn't always a suitable encoding");
	}	
	
	/**
	 * This function converts the given commit value to a byte array. 
	 * @param value
	 * @return the generated bytes.
	 */
	public byte[] generateBytesFromCommitValue(CmtCommitValue value){
		if (!(value instanceof  CmtGroupElementCommitValue))
			throw new IllegalArgumentException("The given value must be of type CmtGroupElementCommitValue");
		return dlog.mapAnyGroupElementToByteArray((GroupElement) value.getX());
	}
			
}