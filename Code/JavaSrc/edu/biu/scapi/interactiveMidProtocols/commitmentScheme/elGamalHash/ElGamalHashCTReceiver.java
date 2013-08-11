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

package edu.biu.scapi.interactiveMidProtocols.committmentScheme.elGamalHash;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.PublicKey;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.InvalidDlogGroupException;
import edu.biu.scapi.exceptions.SecurityLevelException;
import edu.biu.scapi.interactiveMidProtocols.committmentScheme.ByteArrayCommitValue;
import edu.biu.scapi.interactiveMidProtocols.committmentScheme.CTReceiver;
import edu.biu.scapi.interactiveMidProtocols.committmentScheme.CommitValue;
import edu.biu.scapi.interactiveMidProtocols.committmentScheme.elGamal.CTCElGamalCommitmentMessage;
import edu.biu.scapi.interactiveMidProtocols.committmentScheme.elGamal.CTCElGamalDecommitmentMessage;
import edu.biu.scapi.interactiveMidProtocols.committmentScheme.elGamal.ElGamalCTRCore;
import edu.biu.scapi.midLayer.asymmetricCrypto.encryption.ScElGamalOnByteArray;
import edu.biu.scapi.midLayer.ciphertext.AsymmetricCiphertext;
import edu.biu.scapi.midLayer.ciphertext.AsymmetricCiphertextSendableData;
import edu.biu.scapi.midLayer.ciphertext.ElGamalOnByteArrayCiphertext;
import edu.biu.scapi.midLayer.ciphertext.ElGamalOnGroupElementCiphertext;
import edu.biu.scapi.midLayer.plaintext.ByteArrayPlaintext;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.hash.CryptographicHash;
import edu.biu.scapi.primitives.hash.bc.BcSHA224;
import edu.biu.scapi.primitives.kdf.HKDF;
import edu.biu.scapi.primitives.prf.bc.BcHMAC;
import edu.biu.scapi.securityLevel.SecureCommit;
/**
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class ElGamalHashCTReceiver extends ElGamalCTRCore implements CTReceiver, SecureCommit {

	private CryptographicHash hash;

	/**
	 * @param channel
	 * @param dlog
	 * @throws IllegalArgumentException
	 * @throws SecurityLevelException
	 * @throws InvalidDlogGroupException
	 */
	/*public ElGamalHashCTReceiver(Channel channel) throws IllegalArgumentException, SecurityLevelException, InvalidDlogGroupException {
		super(channel);
		hash = new BcSHA224(); 		//This default hash suits the default DlogGroup of the underlying Committer.
	}*/
	/**
	 * @param channel
	 * @param dlog
	 * @throws IllegalArgumentException
	 * @throws SecurityLevelException
	 * @throws InvalidDlogGroupException
	 */
	public ElGamalHashCTReceiver(Channel channel, DlogGroup dlog, CryptographicHash hash) throws IllegalArgumentException, SecurityLevelException, InvalidDlogGroupException {
		super(channel, dlog, new ScElGamalOnByteArray(dlog, new HKDF(new BcHMAC())));
		if (hash.getHashedMsgSize()> (dlog.getOrder().bitLength()/8)){
			throw new IllegalArgumentException("The size in bytes of the resulting hash is bigger than the size in bytes of the order of the DlogGroup.");
		}
		this.hash = hash;

	}
	
	/* (non-Javadoc)
	 * @see edu.biu.scapi.interactiveMidProtocols.committmentScheme.ElGamalCTRCore#processDecommitment(int, edu.biu.scapi.interactiveMidProtocols.committmentScheme.CTCElGamalDecommitmentMessage)
	 */
	@Override
	
	
	protected CommitValue processDecommitment(int id, CTCElGamalDecommitmentMessage msg) {
		
		//Hash the input x with the hash function
		byte[] x  = (byte[]) msg.getX();
		//calculate H(x) = Hash(x)
		byte[] hashValArray = new byte[hash.getHashedMsgSize()];
		hash.update(x, 0, x.length);
		hash.hashFinal(hashValArray, 0);

		//Fetch received commitment according to ID
		CTCElGamalCommitmentMessage receivedCommitment = commitmentMap.get(Integer.valueOf(id));
		PublicKey publicKey = (PublicKey) elGamal.reconstructPublicKey(receivedCommitment.getPublicKey());
		try {
			elGamal.setKey(publicKey);
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		ElGamalOnByteArrayCiphertext c =(ElGamalOnByteArrayCiphertext) elGamal.encryptWithGivenRandomValue(new ByteArrayPlaintext(hashValArray), msg.getR());
		System.out.println("Calculated cipher = " + c);
		ElGamalOnByteArrayCiphertext receivedCommitmentCipher = (ElGamalOnByteArrayCiphertext) elGamal.reconstructCiphertext(receivedCommitment.getCipherData());
		System.out.println("Received cipher = " + receivedCommitmentCipher);
		if (receivedCommitmentCipher.equals(c))
			//The decommitment was accepted by El Gamal core. Now, El Gamal Hash has to return the original value before the hashing.
			return new ByteArrayCommitValue(x);
		return null;
	}
}