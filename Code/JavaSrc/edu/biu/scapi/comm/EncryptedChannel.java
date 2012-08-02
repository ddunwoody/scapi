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
