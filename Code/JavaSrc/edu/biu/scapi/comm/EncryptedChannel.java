/**
 * 
 */
package edu.biu.scapi.comm;

import java.io.IOException;
import java.security.Key;

/** 
 * @author LabTest
 */
class EncryptedChannel extends ChannelDecorator {
	private Key encKey;
	//private EncryptionAlgorithm encryptionAlgo; ?????
	private String algName;

	/** 
	 * @param channel
	 * @param algName
	 * @param setOfKeys
	 */
	EncryptedChannel(Channel channel, String algName/*, SetKey setOfKeys*/) {
		super(channel);
	}

	EncryptedChannel(Channel channel, Key encKey){
		
		super(channel);
		this.encKey = encKey;
	}
	
	
	/** 
	 * @param data
	 */
	private byte[] encrypt(byte[] data) {
		
		//TODO encrypt 
		return data;
		
	}

	/** 
	 * @param data
	 */
	private byte[] decrypt(byte[] data) {
		
		//TODO decrypt
		return data;
	}

	/**
	 * 
	 */
	public Message receive() throws ClassNotFoundException, IOException {
		
		//get the message from the channel
		Message msg = channel.receive();
		
		//decrypt the encrypted message
		msg.setData(decrypt(msg.getData()));
		
		return msg;
	}

	/**
	 * 
	 */
	public void send(Message msg) throws IOException {
		
		//encrypt the message
		msg.setData(encrypt(msg.getData()));
		channel.send(msg);
		
		
	}

	/**
	 * Pass the close request to the attached channel.
	 */
	public void close() {
		
		channel.close();
	}
}