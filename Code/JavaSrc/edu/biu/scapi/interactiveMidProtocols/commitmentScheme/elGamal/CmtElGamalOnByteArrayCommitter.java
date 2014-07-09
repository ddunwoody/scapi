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
package edu.biu.scapi.interactiveMidProtocols.commitmentScheme.elGamal;

import java.io.IOException;
import java.security.SecureRandom;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.CommitValueException;
import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.exceptions.InvalidDlogGroupException;
import edu.biu.scapi.exceptions.SecurityLevelException;
import edu.biu.scapi.generals.ScapiDefaultConfiguration;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtByteArrayCommitValue;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCCommitmentMsg;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCommitter;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCommitValue;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtOnByteArray;
import edu.biu.scapi.midLayer.asymmetricCrypto.encryption.ScElGamalOnByteArray;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.kdf.HKDF;
import edu.biu.scapi.primitives.kdf.KeyDerivationFunction;
import edu.biu.scapi.primitives.prf.bc.BcHMAC;
import edu.biu.scapi.securityLevel.PerfectlyBindingCmt;
import edu.biu.scapi.tools.Factories.DlogGroupFactory;

/**
 * This class implements the committer side of the ElGamal commitment. <p>
 * 
 * It uses El Gamal encryption for byte arrays, that is, the encryption class used is 
 * ScElGamalOnbyteArray. This default cannot be changed.<p>
 * 
 * The pseudo code of this protocol can be found in Protocol 3.4 of pseudo codes document at {@link http://crypto.biu.ac.il/scapi/SDK_Pseudocode_SCAPI_V2.0.0.pdf}.<p>
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class CmtElGamalOnByteArrayCommitter extends CmtElGamalCommitterCore implements CmtCommitter, PerfectlyBindingCmt, CmtOnByteArray {
	
	/**
	 * This constructor lets the caller pass the channel, the dlog group and the 
	 * KeyDerivation function to work with. 
	 * The El Gamal option (ScElGamalOnByteArray)is set by default by the constructor 
	 * and cannot be changed.
	 * @param channel used for the communication
	 * @param dlog	Dlog group
	 * @param kdf key derivation function
	 * @param random
	 * @throws IllegalArgumentException
	 * @throws SecurityLevelException
	 * @throws InvalidDlogGroupException
	 * @throws IOException
	 */
	public CmtElGamalOnByteArrayCommitter(Channel channel, DlogGroup dlog, KeyDerivationFunction kdf, SecureRandom random) throws IllegalArgumentException, SecurityLevelException, InvalidDlogGroupException, IOException{
		super(channel, dlog, new ScElGamalOnByteArray(dlog, kdf), random);
	}

	/**
	 * This constructor uses default Dlog group and El Gamal.
	 * @param channel
	 * @throws IOException
	 */
	public CmtElGamalOnByteArrayCommitter(Channel channel) throws IOException {
		String dlogGroupName = ScapiDefaultConfiguration.getInstance().getProperty("DDHDlogGroup");
		DlogGroup dlogGroup = null;
		KeyDerivationFunction kdf = new HKDF(new BcHMAC());
		//Create the Dlog group
		try {
			dlogGroup = DlogGroupFactory.getInstance().getObject(dlogGroupName);
		} catch (FactoriesException e1) {
			e1.printStackTrace();
		}
		//Proceed with construction of ElGamalCTCCore instance
		try {
			doConstruct(channel, dlogGroup, new ScElGamalOnByteArray(dlogGroup, kdf), new SecureRandom());
		} catch (SecurityLevelException e) {
			e.printStackTrace();
		} catch (InvalidDlogGroupException e) {
			e.printStackTrace();
		}
		
	}
	
	public CmtCCommitmentMsg generateCommitmentMsg(CmtCommitValue input, long id){
		if (!(input instanceof CmtByteArrayCommitValue))
			throw new IllegalArgumentException("The input must be of type CmtByteArrayCommitValue");
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
		if (!(input instanceof CmtByteArrayCommitValue))
			throw new IllegalArgumentException("The input must be of type CmtByteArrayCommitValue");
		super.commit(input, id);
		
	}
	
	/**
	 * This function samples random commit value and returns it.
	 * @return the sampled commit value
	 */
	public CmtCommitValue sampleRandomCommitValue(){
		byte[] val = new byte[32];
		random.nextBytes(val);
		return new CmtByteArrayCommitValue(val);
	}
	
	@Override
	public CmtCommitValue generateCommitValue(byte[] x)throws CommitValueException {
		return new CmtByteArrayCommitValue(x);
	}	
	
	/**
	 * This function converts the given commit value to a byte array. 
	 * @param value
	 * @return the generated bytes.
	 */
	public byte[] generateBytesFromCommitValue(CmtCommitValue value){
		if (!(value instanceof CmtByteArrayCommitValue))
			throw new IllegalArgumentException("The given value must be of type CmtByteArrayCommitValue");
		return (byte[]) value.getX();
	}

}
