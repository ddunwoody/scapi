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
package edu.biu.scapi.interactiveMidProtocols.coinTossing;

import java.io.IOException;
import java.io.Serializable;
import java.security.SecureRandom;

import javax.crypto.SecretKey;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.exceptions.CommitValueException;
import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtWithProofsCommitter;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.CmtCommitValue;
import edu.biu.scapi.interactiveMidProtocols.commitmentScheme.pedersen.CmtPedersenWithProofsCommitter;
import edu.biu.scapi.primitives.kdf.KeyDerivationFunction;
import edu.biu.scapi.securityLevel.Malicious;
import edu.biu.scapi.securityLevel.StandAlone;
import edu.biu.scapi.tools.Factories.KdfFactory;

/**
 * Concrete implementation of a protocol for tossing a string from party one's point of view.<p>
 * This protocol is fully secure under the stand-alone simulation-based definitions.<P>
 * 
 * This protocol is based on: Y. Lindell. Parallel Coin-Tossing and Constant-Round Secure Two-Party Computation. CRYPTO 2001.<p>
 * 
 * The pseudo code of this protocol can be found in Protocol 6.2 of pseudo codes document at {@link http://crypto.biu.ac.il/scapi/SDK_Pseudocode_SCAPI_V2.0.0.pdf}.<p>
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class CTStringPartyOne implements CTPartyOne, StandAlone, Malicious{
	
	private Channel channel;
	private CmtWithProofsCommitter committer;
	private SecureRandom random;
	private int l;
	private KeyDerivationFunction kdf;
	
	/**
	 * Constructor that set the given parameters.
	 * @param channel used to communicate between two parties.
	 * @param committer that also has ZK proofs.
	 * @param kdf Key Derivation Function
	 * @param l determining the length of the output
	 * @param random source of randomness
	 */
	public CTStringPartyOne(Channel channel, CmtWithProofsCommitter committer, 
			KeyDerivationFunction kdf, int l, SecureRandom random) {
		
		doConstruct(channel, committer, kdf, l, random);
	}

	
	/**
	 * Default constructor that creates committer and KDF with default parameters.
	 * @param channel used to communicate between two parties.
	 * @param l determining the length of the output
	 * @throws CheatAttemptException 
	 * @throws IOException 
	 * @throws ClassNotFoundException 
	 */
	public CTStringPartyOne(Channel channel, int l) throws ClassNotFoundException, IOException, CheatAttemptException  {
		
		try {
			kdf = KdfFactory.getInstance().getObject("HKDF(HMac(SHA-256))");
		} catch (FactoriesException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		};
		
		doConstruct(channel, new CmtPedersenWithProofsCommitter(channel), kdf, l, new SecureRandom());
	}

	/**
	 * Sets the given parameters.
	 * @param channel used to communicate between two parties.
	 * @param committer that also has ZK proofs.
	 * @param kdf Key Derivation Function
	 * @param l determining the length of the output
	 * @param random source of randomness
	 */
	private void doConstruct(Channel channel, CmtWithProofsCommitter committer, 
			KeyDerivationFunction kdf, int l, SecureRandom random)  {
		this.committer = committer;
		this.kdf = kdf;
		this.channel = channel;
		this.random = random;
		this.l = l;
	}
	
	/**
	 * Execute the following protocol:<p>
	 * "SAMPLE a random L-bit string s1 <- {0,1}^L<p>
	 *	RUN subprotocol COMMIT.commit on s1<p>
	 *	RUN the prover in a ZKPOK_FROM_SIGMA applied to a SIGMA protocol that P1 knows the committed value s1<p>
	 *	WAIT for an L-bit string s2 from P2<p>
	 *	SEND s1 to P2<p>
	 *	RUN the prover in ZK_FROM_SIGMA applied to a SIGMA protocol that the committed value was s1<p>
	 *	OUTPUT s1 XOR s2".
	 */
	public CTOutput toss() throws IOException, CheatAttemptException, ClassNotFoundException, CommitValueException {
		//Sample a random L-bit string s1 <- {0,1}^L 
		CmtCommitValue s1 = committer.sampleRandomCommitValue();
				
		//Run sub protocol COMMIT.commit on b1.
		long id = random.nextLong();
		committer.commit(s1, id);
		
		//Run the prover in a ZKPOK_FROM_SIGMA applied to a SIGMA protocol that P1 knows the committed value s1
		committer.proveKnowledge(id);
		
		//Receive s2 from party two.
		byte[] s2 = receiveS2();
		if (s2.length != l/8){
			throw new IllegalArgumentException("the length of the given s2 is not l-bit");
		}
		
		//Run the prover in ZK_FROM_SIGMA applied to a SIGMA protocol that the committed value was s1
		committer.proveCommittedValue(id);
		
		//Compute s1 XOR s2
		byte[] s1Bytes = computeKdf(committer.generateBytesFromCommitValue(s1));
		byte[] result = new byte[l/8];
		for (int i=0; i<l/8; i++){
			result[i] = (byte) (s1Bytes[i] ^ s2[i]);
		}
		//Return the output
		return new CTStringOutput(result);
	}
	
	/**
	 * Receives s2 from party two.
	 * @return the received byte array
	 * @throws ClassNotFoundException
	 * @throws IOException
	 */
	private byte[] receiveS2() throws ClassNotFoundException, IOException {
		Serializable s2;
		try {
			s2 = channel.receive();
		} catch (IOException e) {
			throw new IOException("Failed to receive s2. The thrown message is: " + e.getMessage());
		}
		if (!(s2 instanceof byte[])){
			throw new IllegalArgumentException("The received s2 is not an instance of byte[]");
		}
		
		return (byte[]) s2;
	}

	/**
	 * Computes the kdf operation on the given byte array in order to get a L-bit byte array.
	 * @param s1Bytes array to compute the kdf operation on.
	 * @return a L-bit byte array.
	 */
	private byte[] computeKdf(byte[] s1Bytes) {
		//KDF get outLen in bytes. In this case, l/8.
		SecretKey lBitsArray = kdf.deriveKey(s1Bytes, 0, s1Bytes.length, l/8);
		return lBitsArray.getEncoded();
	}
}
