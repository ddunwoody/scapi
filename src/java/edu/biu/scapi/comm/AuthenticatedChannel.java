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
import edu.biu.scapi.midLayer.symmetricCrypto.mac.Mac;
import edu.biu.scapi.midLayer.symmetricCrypto.mac.TaggedObject;
import edu.biu.scapi.securityLevel.UnlimitedTimes;

/** 
 * This channel ensures UnlimitedTimes security level. The owner of the channel is responsible for setting the MAC algorithm to use and make sure the 
 * the MAC is initialized with a suitable key. Then, every message sent via this channel is authenticated using the underlying MAC algorithm and every message received is verified by it.<p>
 * The user needs not to worry about any of the authentication and verification tasks. The owner of this channel can rest assure that when an object gets sent over this channel 
 * it gets authenticated with the defined MAC algorithm. In the same way, when receiving a message sent over this channel (which was authenticated by the other party) 
 * the owner of the channel receives an already verified and plain object. 
 *    
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 */
public class AuthenticatedChannel extends ChannelDecorator {

	Mac macAlg; //The MAC used to authenticate the messages sent by this channel
	
	/**
	 * This constructor can only be used by SCAPI's CommunicationSetup class.
	 * @param ipAddress the IP address to connect to
	 * @param port the port to connect to
	 * @param mac the MAC algorithm required to authenticate the messages sent by this channel
	 * @throws SecurityLevelException if the MAC algorithm passed is not UnlimitedTimes-secure
	 */
	AuthenticatedChannel(InetAddress ipAddress, int port, Mac mac) throws SecurityLevelException{
		super(new PlainTCPChannel(ipAddress,  port));
		doConstruct(mac);
	}
	
	/**
	 * This constructor can only be used by SCAPI's CommunicationSetup class.
	 * @param socketAddress object that has the IP address and port to connect to
	 * @param mac the MAC algorithm required to authenticate the messages sent by this channel
	 * @throws SecurityLevelException if the MAC algorithm passed is not UnlimitedTimes-secure
	 */
	AuthenticatedChannel(InetSocketAddress socketAddress, Mac mac) throws SecurityLevelException{
		super(new PlainTCPChannel(socketAddress));
		doConstruct(mac);
	}
	
	
	/** 
	 * This public constructor can be used by anyone holding a channel that is connected. Such a channel can be obtained by running the prepareForCommunications function
	 * of {@link CommunicationSetup} which returns a set of already connected channels. (Note that {@link PlainTCPChannel} does not have a public constructor, if you wish to establish
	 * a connection without the CommunicationSetup you will need to write your own Channel class).<p>
	 *   
	 * @param channel an already connected channel
	 * @param mac the MAC algorithm required to authenticate the messages sent by this channel
	 * @throws SecurityLevelException if the MAC algorithm passed is not UnlimitedTimes-secure
	 */
	public AuthenticatedChannel(Channel channel, Mac mac) throws SecurityLevelException {
		super(channel);	
		doConstruct(mac);
	}
	
	//This function checks that the MAC algorithm passed is UnlimitedTimes-secure. If so, it continues constructing the object, otherwise it throws exception.
	private void doConstruct(Mac macAlg) throws SecurityLevelException{
		if (! (macAlg instanceof UnlimitedTimes ))
			throw new SecurityLevelException("The encryption scheme passed is not CPA-secure");	
		this.macAlg = macAlg;
	}

	
	/**
	 * Sets the key of the underlying MAC algorithm. This function must be called before sending or receiving messages if the MAC algorithm passed to this
	 * channel had not been set with a key yet. The key can be set indefinite number of times depending on the needs of the application. 
	 * @param key a suitable SecretKey
	 * @throws InvalidKeyException if the given key does not match the underlying MAC algorithm.
	 */
	public void setKey( SecretKey key) throws InvalidKeyException{
		this.macAlg.setKey(key);
	}
	
	
	/**
	 * Receives an authenticated message sent by the other party. It then verifies the message and returns the actual message without the MAC tag.
	 * The caller of this function needs NOT to worry at all about the verification of the message, all the work is performed inside the channel
	 * @return <B> the actual object </B> sent by the other party, if the message verifies<p>
	 * 		   <B>{@code null}</B> if the message does not verify	  
	 */
	public Serializable receive() throws ClassNotFoundException, IOException {
		//Since this is an authenticated channel, the other side must have sent a TaggedObject containing 
		//1) the Serialized version of the actual object that the user meant to send,
		//2) the tag that we are going to use to verify that the object hasn't been tampered with.
		
		//Try to cast the received message to a TaggedObject.
		TaggedObject taggedObj = (TaggedObject) channel.receive();
		
		//Verify the serialized object with the tag
		boolean isVerified;
		isVerified = macAlg.verify(taggedObj.getObject(), 0, taggedObj.getObject().length, taggedObj.getTag());
		
		//If the object doesn't verify, then return null!!
		if(!isVerified)
			return null;
		
		//Deserialize the object. The caller of this function doesn't need to know anything about authentication, therefore he should get 
		//the plain object that was sent by the sender.
		ByteArrayInputStream bStream = new ByteArrayInputStream(taggedObj.getObject());
		ObjectInputStream ois = new ObjectInputStream(bStream);
		
		return  (Serializable) ois.readObject();
		
	}
	

	/**
	 * Sends an authenticated message on the channel, using the underlying MAC algorithm. The caller of this function needs NOT to worry at all about the authentication,
	 * all the work is performed inside the channel
	 * @param msg the object to send to the other party  AS IS, the only constraint is that it must be Serializable
	 */
	public void send(Serializable msg) throws IOException {
		
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		ObjectOutputStream oos = new ObjectOutputStream(bos);
		//Serialize msg:
		oos.writeObject(msg);
		//Now retrieve "serialized" msg from bos:
		byte[] serializedMsg = bos.toByteArray();
		byte[] tag = macAlg.mac(serializedMsg, 0, serializedMsg.length);
		
		TaggedObject taggedObj = new TaggedObject(serializedMsg, tag);
		//Send the tagged object
		channel.send(taggedObj);
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
