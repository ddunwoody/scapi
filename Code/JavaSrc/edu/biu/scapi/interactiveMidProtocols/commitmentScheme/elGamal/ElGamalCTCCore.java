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
package edu.biu.scapi.interactiveMidProtocols.committmentScheme.elGamal;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.Hashtable;
import java.util.Map;

import org.bouncycastle.util.BigIntegers;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.exceptions.InvalidDlogGroupException;
import edu.biu.scapi.exceptions.SecurityLevelException;
import edu.biu.scapi.interactiveMidProtocols.committmentScheme.ByteArrayCommitValue;
import edu.biu.scapi.interactiveMidProtocols.committmentScheme.CTCDecommitmentMessage;
import edu.biu.scapi.interactiveMidProtocols.committmentScheme.CommitValue;
import edu.biu.scapi.interactiveMidProtocols.committmentScheme.CommitmentPair;
import edu.biu.scapi.interactiveMidProtocols.committmentScheme.GroupElementCommitValue;
import edu.biu.scapi.midLayer.asymmetricCrypto.encryption.ElGamalEnc;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.ScElGamalPrivateKey;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.ScElGamalPublicKey;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.ScElGamalPublicKey.ScElGamalPublicKeySendableData;
import edu.biu.scapi.midLayer.ciphertext.AsymmetricCiphertext;
import edu.biu.scapi.midLayer.ciphertext.ElGamalCiphertextSendableData;
import edu.biu.scapi.midLayer.ciphertext.ElGamalOnGroupElementCiphertext;
import edu.biu.scapi.midLayer.plaintext.BigIntegerPlainText;
import edu.biu.scapi.midLayer.plaintext.ByteArrayPlaintext;
import edu.biu.scapi.midLayer.plaintext.GroupElementPlaintext;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.dlog.cryptopp.CryptoPpDlogZpSafePrime;
import edu.biu.scapi.primitives.dlog.miracl.MiraclDlogECF2m;
import edu.biu.scapi.securityLevel.DDH;

/**
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public abstract class ElGamalCTCCore {
	protected Channel channel;
	protected DlogGroup dlog;
	private SecureRandom random;
	private BigInteger qMinusOne;
	protected Map<Integer, CommitmentPair> commitmentMap;
	protected ElGamalEnc elGamal;
	protected ScElGamalPublicKey publicKey;
	protected ScElGamalPrivateKey privateKey;



	
	ElGamalCTCCore(Channel channel, ElGamalEnc elGamal) throws IllegalArgumentException, SecurityLevelException, InvalidDlogGroupException{
		try {
			//Uses Miracl Koblitz 233 Elliptic curve.
			doConstruct(channel, new MiraclDlogECF2m("K-233"), new SecureRandom(), elGamal);
		} catch (IOException e) {
			//Why do we have this??

			//If there is a problem with the elliptic curves file, create Zp DlogGroup.
			doConstruct(channel, new CryptoPpDlogZpSafePrime(), new SecureRandom(), elGamal);
		}
	}

	protected ElGamalCTCCore(Channel channel, DlogGroup dlog, ElGamalEnc elGamal) throws IllegalArgumentException, SecurityLevelException, InvalidDlogGroupException{
		doConstruct(channel, dlog, new SecureRandom(), elGamal);
	}



	private void doConstruct(Channel channel, DlogGroup dlog, SecureRandom random, ElGamalEnc elGamal) throws SecurityLevelException, InvalidDlogGroupException{
		//The underlying dlog group must be DDH secure.
		if (!(dlog instanceof DDH)){
			throw new SecurityLevelException("DlogGroup should have DDH security level");
		}
		if(!dlog.validateGroup())
			throw new InvalidDlogGroupException();

		this.channel = channel;
		this.dlog = dlog;
		this.random = random;
		qMinusOne =  dlog.getOrder().subtract(BigInteger.ONE);
		commitmentMap = new Hashtable<Integer, CommitmentPair>();
		//elGamal = new ScElGamalOnGroupElement(dlog);
		this.elGamal = elGamal;
	}

	/* (non-Javadoc)
	 * @see edu.biu.scapi.interactiveMidProtocols.committmentScheme.CTCommitter#preProcess()
	 */
	public void preProcess() throws ClassNotFoundException, IOException, CheatAttemptException {
		KeyPair pair = elGamal.generateKey();
		publicKey = (ScElGamalPublicKey) pair.getPublic();
		privateKey = (ScElGamalPrivateKey) pair.getPrivate();
		try {
			elGamal.setKey(publicKey, privateKey);
		} catch (InvalidKeyException e) {
			//Catch the exception since it should not happen.
			System.out.println("The KeyPair generated by this instance of ElGamal is not valid: " + e.getMessage());
		}
	}


	public void commit(CommitValue input, int id) throws IOException {

		BigInteger r = sampleRandomValues();	

		AsymmetricCiphertext c =  elGamal.encryptWithGivenRandomValue(input.convertToPlaintext(), r);

		try {
			//Send the message by the channel.
			channel.send(new CTCElGamalCommitmentMessage((ScElGamalPublicKeySendableData) publicKey.generateSendableData(),  (ElGamalCiphertextSendableData)c.generateSendableData(), id));
		} catch (IOException e) {
			throw new IOException("failed to send the message. The error is: " + e.getMessage());
		}	
		//After succeeding in sending the commitment, keep the committed value in the map together with its ID.
		commitmentMap.put(Integer.valueOf(id), new CommitmentPair(r, input));
		System.out.println("h = " + ((ScElGamalPublicKey)publicKey).getH().toString());
		System.out.println("a = " + ((ScElGamalPrivateKey)privateKey).getX().toString());
		System.out.println("x = " + input.getX());
		System.out.println("r = " + r);
		System.out.println("cipher = " + c);
	}

	//This function is for testing purposes only. It should be deleted before publishing this part of SCAPI.
	//To be used immediately after commit function.
	public Object getCommitment(int id){
		CommitmentPair pair = commitmentMap.get(Integer.valueOf(id));
		AsymmetricCiphertext c = null;
		if( pair.getX() instanceof GroupElementCommitValue){
			GroupElement x = ((GroupElementCommitValue)pair.getX()).getX();
			c = elGamal.encryptWithGivenRandomValue(new GroupElementPlaintext(x), pair.getR());
		}
		else if( pair.getX() instanceof BigInteger)
			c = elGamal.encryptWithGivenRandomValue(new BigIntegerPlainText((BigInteger)pair.getX()), pair.getR());
		else c = elGamal.encryptWithGivenRandomValue(new ByteArrayPlaintext(((ByteArrayCommitValue) pair.getX()).getX()), pair.getR());
		return c;
	}

	/* (non-Javadoc)
	 * @see edu.biu.scapi.interactiveMidProtocols.committmentScheme.CTCommitter#decommit(int)
	 */
	public void decommit(int id) throws IOException {

		try{
			channel.send((CTCElGamalDecommitmentMessage)computeDecommit(id));
		}
		catch (IOException e) {
			throw new IOException("failed to send the message. The error is: " + e.getMessage());
		}
		//This is not according to the pseudo-code but for our programming needs. TODO Check if can be left.
		//return (CTCDecommitmentMessage) msg;
	}	

	CTCDecommitmentMessage computeDecommit(int id){
		//fetch the commitment according to the requested ID
		CommitmentPair pair = commitmentMap.get(Integer.valueOf(id));
		return (CTCDecommitmentMessage) new CTCElGamalDecommitmentMessage(pair.getX().generateSendableData(),pair.getR());
	}

	private BigInteger sampleRandomValues() {
		BigInteger r = BigIntegers.createRandomInRange(BigInteger.ZERO, qMinusOne, random);
		return r;
	}

	private ElGamalOnGroupElementCiphertext computeCommittment(GroupElement x, BigInteger r){
		return (ElGamalOnGroupElementCiphertext) elGamal.encryptWithGivenRandomValue(new GroupElementPlaintext(x), r);
	}
}

