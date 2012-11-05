/**
* This file is part of SCAPI.
* SCAPI is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
* SCAPI is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
* You should have received a copy of the GNU General Public License along with SCAPI.  If not, see <http://www.gnu.org/licenses/>.
*
* Any publication and/or code referring to and/or based on SCAPI must contain an appropriate citation to SCAPI, including a reference to http://crypto.cs.biu.ac.il/SCAPI.
*
* SCAPI uses Crypto++, Miracl, NTL and Bouncy Castle. Please see these projects for any further licensing issues.
*
*/
/**
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
import java.security.Key;

import javax.crypto.SecretKey;

import edu.biu.scapi.midLayer.symmetricCrypto.encryption.SymmetricEnc;
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
