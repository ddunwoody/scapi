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



package edu.biu.scapi.comm;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.InvalidKeyException;

import javax.crypto.SecretKey;

import edu.biu.scapi.exceptions.SecurityLevelException;
import edu.biu.scapi.midLayer.ciphertext.SymmetricCiphertext;
import edu.biu.scapi.midLayer.plaintext.ByteArrayPlaintext;
import edu.biu.scapi.midLayer.symmetricCrypto.encryption.SymmetricEnc;
import edu.biu.scapi.securityLevel.Cpa;

/** 
 * This channel ensures CPA security level. The owner of the channel is responsible for setting the encryption scheme to use and make sure the 
 * the encryption scheme is initialized with a suitable key. Then, every message sent via this channel is encrypted and decrypted using the underlying encryption scheme.<p>
 * The user needs not to worry about any of the encryption or decryption tasks. The owner of this channel can rest assure that when an object gets sent over this channel 
 * it gets encrypted with the defined encryption scheme. In the same way, when receiving a message sent over this channel (which was encrypted by the other party) 
 * the owner of the channel receives an already decrypted object. 
 *    
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 */
public class EncryptedChannel extends ChannelDecorator {
	private SymmetricEnc encScheme; 

	/**
	 * This constructor can only be used by SCAPI's CommunicationSetup class.
	 * Creates a new EncryptedChannel. The channel is connected between the local host and the IP address and port specified as arguments. The encryption scheme must be CPA-secure, otherwise
	 * an exception is thrown. The encryption scheme does not need to be initialized with a key at this moment (even though it can), but before sending or receiving a message over this channel
	 * the relevant secret key must be set.
	 *   
	 * @param ipAddress other party's IP address
	 * @param port other party's port
	 * @param encScheme a symmetric encryption scheme that is CPA-secure.
	 * @throws SecurityLevelException if the encryption scheme is not CPA-secure 
	 */
	EncryptedChannel(InetAddress ipAddress, int port, SymmetricEnc encScheme) throws SecurityLevelException{
		super(new PlainTCPChannel(ipAddress,  port));
		doConstruct( encScheme);
	}
	
	/**
	 * This constructor can only be used by SCAPI's CommunicationSetup class.
	 * Creates a new EncryptedChannel. The channel is connected between the local host and the IP address and port specified as arguments. The encryption scheme must be CPA-secure, otherwise
	 * an exception is thrown. The encryption scheme does not need to be initialized with a key at this moment (even though it can), but before sending or receiving a message over this channel
	 * the relevant secret key must be set.
	 *   
	 * @param socketAddress object containing other party's IP address and port
	 * @param encScheme a symmetric encryption scheme that is CPA-secure.
	 * @throws SecurityLevelException if the encryption scheme is not CPA-secure 
	 */
	EncryptedChannel(InetSocketAddress socketAddress, SymmetricEnc encScheme) throws SecurityLevelException{
		super(new PlainTCPChannel(socketAddress));
		doConstruct( encScheme);
	}
	
	/**
	 * This public constructor can be used by anyone holding a channel that is connected. Such a channel can be obtained by running the prepareForCommunications function
	 * of {@link CommunicationSetup} which returns a set of already connected channels. (Note that {@link PlainTCPChannel} does not have a public constructor, if you wish to establish
	 * a connection without the CommunicationSetup you will need to write your own Channel class).<p>
	 * Creates a new EncryptedChannel that wraps the already connected channel mentioned above. The encryption scheme must be CPA-secure, otherwise
	 * an exception is thrown. The encryption scheme does not need to be initialized with a key at this moment (even though it can), but before sending or receiving a message over this channel
	 * the relevant secret key must be set.
	 *   
	 * @param channel an already connected channel
	 * @param encScheme a symmetric encryption scheme that is CPA-secure.
	 * @throws SecurityLevelException if the encryption scheme is not CPA-secure 
	 */
	public EncryptedChannel(Channel channel, SymmetricEnc encScheme) throws SecurityLevelException {
		super(channel);
		doConstruct( encScheme);
	}

	//This function checks that the encryption scheme passed is CPA-secure. If so, it continues constructing the object, otherwise it throws exception.
	private void doConstruct(SymmetricEnc encScheme) throws SecurityLevelException{
		if (! (encScheme instanceof Cpa))
			throw new SecurityLevelException("The encryption scheme passed is not CPA-secure");	
		this.encScheme = encScheme;
	}
	
	/**
	 * Sets the key of the underlying encryption scheme. This function must be called before sending or receiving messages if the encryption scheme passed to this
	 * channel had not been set with a key yet. The key can be set indefinite number of times depending on the needs of the application. 
	 * @param key a suitable SecretKey
	 * @throws InvalidKeyException if the given key does not match the underlying MAC algorithm.
	 */
	public void setKey( SecretKey key) throws InvalidKeyException{
		this.encScheme.setKey(key);
	}
	
	
	/**
	 * Receives an encrypted message sent by the other party. It then decrypts the message and returns the actual message object sent by the other party.
	 * The caller of this function needs NOT to worry at all about the decryption of the message, all the work is performed inside the channel
	 * @return the decrypted object sent by the other party
	 * 		     
	 */
	public Serializable receive() throws ClassNotFoundException, IOException {
		
		//Get the message from the channel
		Serializable rcvMsg = (Serializable)  channel.receive(); 
		SymmetricCiphertext cipher = (SymmetricCiphertext)rcvMsg;
		//Decrypt the encrypted message
		ByteArrayPlaintext msg = (ByteArrayPlaintext) encScheme.decrypt(cipher);
		
		//Deserialize the object. The caller of this function doesn't need to know anything about encryption, therefore he should get
		//the plain object that was sent by the sender.
		ByteArrayInputStream bStream = new ByteArrayInputStream(msg.getText());
		ObjectInputStream ois = new ObjectInputStream(bStream);
				
		return  (Serializable) ois.readObject();
	}

	/**
	 * Sends an encrypted message on the channel, using the underlying encryption scehme. The caller of this function needs NOT to worry at all about the encryption,
	 * all the work is performed inside the channel
	 * @param msg the object to send to the other party  AS IS, the only constraint is that it must be Serializable
	 */
	public void send(Serializable msg) throws IOException {
		//The user of this channel should not need to worry about the details of how the encryption is performed and what elements
		//are needed to encrypt. All this work is done here, hidden from the user. From the user's perspective, she's sending her message on an encrypted channel and that is all 
		//she cares about.

		//Utilize the Serialization technique to obtain a stream of bytes representing the object that needs to be sent on the channel.
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		ObjectOutputStream oos = new ObjectOutputStream(bos);
		//"Serialize" msg:
		oos.writeObject(msg);
		//Now retrieve "serialized" msg from bos:
		byte[] serializedMsg = bos.toByteArray();
		
		//Generate a suitable Plaintext object from the "serialized" message to be sent.
		ByteArrayPlaintext plainText = new ByteArrayPlaintext(serializedMsg);
		//Encrypt the plaintext and send ciphertext obtained. (On the other side of the channel, an encrypted message or ciphertext will be received by the channel, 
		//but what the caller of the function channel::receive will get is the correct decrypted and deserialized object).
		SymmetricCiphertext cipher = encScheme.encrypt(plainText);
		channel.send((Serializable)cipher);
	}

	/**
	 * Close the channel.
	 */
	public void close() {
		
		channel.close();
	}

	/* (non-Javadoc)
	 * @see edu.biu.scapi.comm.Channel#isClosed()
	 */
	@Override
	public boolean isClosed() {
		return this.channel.isClosed();
	}
}
