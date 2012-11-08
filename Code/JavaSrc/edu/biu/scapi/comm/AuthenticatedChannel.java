/**
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
* Copyright (c) 2012 - SCAPI (http://crypto.biu.ac.il/scapi)
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

import edu.biu.scapi.midLayer.symmetricCrypto.mac.Mac;
import edu.biu.scapi.midLayer.symmetricCrypto.mac.TaggedObject;

/** 
 * @author LabTest
 */
class AuthenticatedChannel extends ChannelDecorator {

	//Key authKey;
	Mac macAlg;
	
	/**
	 * 
	 *  
	 */
	AuthenticatedChannel(InetAddress ipAddress, int port, Mac mac){
		super(new PlainTCPChannel(ipAddress,  port));
		this.macAlg = mac;
	}
	
	AuthenticatedChannel(InetSocketAddress socketAddress, Mac mac){
		super(new PlainTCPChannel(socketAddress));
		this.macAlg = mac;
	}
	
	
	/** 
	 * @param channel
	 * @param digSign
	 * @param setOfKeys
	 */
	AuthenticatedChannel(Channel channel, Mac mac) {
		super(channel);	
		this.macAlg = mac;
	}
	
	public void setKey( SecretKey key) throws InvalidKeyException{
		this.macAlg.setKey(key);
	}
	

	/** 
	 * @param data
	 */
	private byte[] sign(byte[] data) {
	
		//TODO perform sign
		return data;
	}

	/** 
	 * @param data
	 */
	private void verify(byte[] data) {
		
	}
	
	/**
	 * Receives a message. Since the message is authenticated you should un-mac the message before reading it.
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
		
		//Deserialize the object. The caller of this function doesn't need to know anything about authentication, therfore he should 
		//the plain object that was sent by the sender.
		ByteArrayInputStream bStream = new ByteArrayInputStream(taggedObj.getObject());
		ObjectInputStream ois = new ObjectInputStream(bStream);
		
		return  (Serializable) ois.readObject();
		
	}
	

	/**
	 * Sends a message on the channel. Before sending it by passing it to the channel mac the message.
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
	 * Pass the close request to the attached channel
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
