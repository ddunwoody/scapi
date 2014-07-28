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

package edu.biu.scapi.interactiveMidProtocols.commitmentScheme.elGamalHash;

import java.io.IOException;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.exceptions.InvalidDlogGroupException;
import edu.biu.scapi.exceptions.SecurityLevelException;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtByteArrayCommitValue;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCCommitmentMsg;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCDecommitmentMessage;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtReceiver;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCommitValue;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtOnByteArray;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.elGamal.CmtElGamalCommitmentMessage;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.elGamal.CmtElGamalDecommitmentMessage;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.elGamal.CmtElGamalReceiverCore;
import edu.biu.scapi.midLayer.asymmetricCrypto.encryption.ScElGamalOnByteArray;
import edu.biu.scapi.midLayer.ciphertext.ElGamalOnByteArrayCiphertext;
import edu.biu.scapi.midLayer.plaintext.ByteArrayPlaintext;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.miracl.MiraclDlogECF2m;
import edu.biu.scapi.primitives.hash.CryptographicHash;
import edu.biu.scapi.primitives.hash.openSSL.OpenSSLSHA256;
import edu.biu.scapi.primitives.kdf.HKDF;
import edu.biu.scapi.primitives.prf.bc.BcHMAC;
import edu.biu.scapi.securityLevel.SecureCommit;

/**
 * This class implements the committer side of the ElGamal hash commitment. <p>
 * 
 * The pseudo code of this protocol can be found in Protocol 3.5 of pseudo codes document at {@link http://crypto.biu.ac.il/scapi/SDK_Pseudocode_SCAPI_V2.0.0.pdf}.<p>
 * 
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class CmtElGamalHashReceiver extends CmtElGamalReceiverCore implements CmtReceiver, SecureCommit, CmtOnByteArray {

	/*
	 * runs the following protocol:
	 * "Run COMMIT_ELGAMAL to commit to value H(x). 
	 * For decommitment, send x and the receiver verifies that the commitment was to H(x)".
	 */
	
	private CryptographicHash hash;

	/**
	 * This constructor receives as argument the channel and chosses default values of 
	 * Dlog Group and Cryptographic Hash such that they keep the condition that the size in 
	 * bytes of the resulting hash is less than the size in bytes of the order of the DlogGroup.
	 * Otherwise, it throws IllegalArgumentException.
	 * An established channel has to be provided by the user of the class.
	 * @param channel
	 * @throws IOException
	 * @throws CheatAttemptException 
	 * @throws ClassNotFoundException 
	 */
	public CmtElGamalHashReceiver(Channel channel) throws IOException, ClassNotFoundException, CheatAttemptException{
		//This default hash suits the default DlogGroup.
		try {
			doConstruct(channel, new MiraclDlogECF2m("K-283"), new OpenSSLSHA256());
		} catch (SecurityLevelException e) {
			// Should not occur since the default DlogGroup has the necessary security level.
		} catch (InvalidDlogGroupException e) {
			// Should not occur since the default DlogGroup is valid.
		}
	}
	
	/**
	 * This constructor receives as arguments an instance of a Dlog Group and an instance 
	 * of a Cryptographic Hash such that they keep the condition that the size in bytes 
	 * of the resulting hash is less than the size in bytes of the order of the DlogGroup.
	 * Otherwise, it throws IllegalArgumentException.
	 * An established channel has to be provided by the user of the class.
	 * @param channel
	 * @param dlog
	 * @param hash
	 * @throws IllegalArgumentException
	 * @throws SecurityLevelException
	 * @throws InvalidDlogGroupException
	 * @throws CheatAttemptException 
	 * @throws IOException 
	 * @throws ClassNotFoundException
	 */
	public CmtElGamalHashReceiver(Channel channel, DlogGroup dlog, CryptographicHash hash) throws IllegalArgumentException, SecurityLevelException, InvalidDlogGroupException, ClassNotFoundException, IOException, CheatAttemptException {
		doConstruct(channel, dlog, hash);

	}

	private void doConstruct(Channel channel, DlogGroup dlog, CryptographicHash hash) throws SecurityLevelException,
			InvalidDlogGroupException, ClassNotFoundException, IOException,	CheatAttemptException {
		super.doConstruct(channel, dlog, new ScElGamalOnByteArray(dlog, new HKDF(new BcHMAC())));
		if (hash.getHashedMsgSize()> (dlog.getOrder().bitLength()/8)){
			throw new IllegalArgumentException("The size in bytes of the resulting hash is bigger than the size in bytes of the order of the DlogGroup.");
		}
		this.hash = hash;
	}
	
	/**
	 * Verifies that the commitment was to H(x).
	 */
	@Override
	public CmtCommitValue verifyDecommitment(CmtCCommitmentMsg commitmentMsg, CmtCDecommitmentMessage decommitmentMsg) {
		if (!(decommitmentMsg instanceof CmtElGamalDecommitmentMessage)){
			throw new IllegalArgumentException("decommitmentMsg should be an instance of CmtElGamalDecommitmentMessage");
		}
		if (!(commitmentMsg instanceof CmtElGamalCommitmentMessage)){
			throw new IllegalArgumentException("commitmentMsg should be an instance of CmtElGamalCommitmentMessage");
		}
		
		//Hash the input x with the hash function
		byte[] x  = (byte[]) decommitmentMsg.getX();
		//calculate H(x) = Hash(x)
		byte[] hashValArray = new byte[hash.getHashedMsgSize()];
		hash.update(x, 0, x.length);
		hash.hashFinal(hashValArray, 0);

		//Fetch received commitment according to ID
		ElGamalOnByteArrayCiphertext c =(ElGamalOnByteArrayCiphertext) elGamal.encrypt(new ByteArrayPlaintext(hashValArray), ((CmtElGamalDecommitmentMessage) decommitmentMsg).getR().getR());
		
		ElGamalOnByteArrayCiphertext receivedCommitmentCipher = (ElGamalOnByteArrayCiphertext) elGamal.reconstructCiphertext(((CmtElGamalCommitmentMessage) commitmentMsg).getCommitment());
		
		if (receivedCommitmentCipher.equals(c))
			//The decommitment was accepted by El Gamal core. Now, El Gamal Hash has to return the original value before the hashing.
			return new CmtByteArrayCommitValue(x);
		return null;
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