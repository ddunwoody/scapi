/**
 * 
 */
package edu.biu.scapi.comm;

import java.io.IOException;
import java.security.Key;

/** 
 * @author LabTest
 */
class AuthenticatedChannel extends ChannelDecorator {
	//private DigitalSignature digitalSignature;

	Key authKey;
	
	/** 
	 * @param channel
	 * @param digSign
	 * @param setOfKeys
	 */
	AuthenticatedChannel(Channel channel/*, DigitalSignature digSign,	SetKey setOfKeys*/) {
		super(channel);	
	}
	
	AuthenticatedChannel(Channel channel, Key authKey){
		super(channel);
		this.authKey = authKey;
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
	public Message receive() throws ClassNotFoundException, IOException {
		
		//get the message from the channel
		Message msg = channel.receive();
		
		//unmac the authenticated message
		
		return msg;
	}

	/**
	 * Sends a message on the channel. Before sending it by passing it to the channel mac the message.
	 */
	public void send(Message msg) throws IOException {
		
		//mac the message
		msg.setData(sign(msg.getData()));
		
		channel.send(msg);
		
		
	}

	/**
	 * Pass the close request to the attached channel
	 */
	public void close() {

		channel.close();
		
	}


}