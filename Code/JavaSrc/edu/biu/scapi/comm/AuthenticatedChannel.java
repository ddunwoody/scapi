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
