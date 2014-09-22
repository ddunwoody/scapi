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



/**
 * A SecuringConnectionThread is created by the CommunicationSetup for each party in the input list. 
 * Its job is to establish a physical connection if it is initialized to do so, as well as securing the connection by performing a key 
 * exchange if needed. 
 * For the sake of simplicity, we unify both roles and call this thread SecuringConnectionThread. 
 * The SecuringConnectionThread is needed only for connecting and securing the connection. 
 * Once the securing stage is finished, the thread reaches the end of the run() function, returns from it and dies. 
 * In order for two parties to be able to connect to each other, one needs to be listening for connections and the other needs to connect to it. 
 * In our case it is not relevant which party connects to which, since all parties are equal (this is not a server-client setup). 
 * We devised a simple algorithm to decide the order of the connections:
 * 	� Each party connects to other parties with higher ID number and *
 *  � Listens to parties with lower ID number than its own. *
 * The comparison will be performed based on the string representation of the InetSocketAddress object obtained from the IP and port of the party.
 * If a party needs to listen for connections, we call it a DOWN connection. 
 * If it needs to connect to a higher up party, we call it an UP connection. 
 * The thread will engage in a loop to try to connect. The loop will end either if the connection succeeds or if it is stopped by the object that created the thread, that is, the CommunicationSetup.
 */
package edu.biu.scapi.comm;

import java.io.IOException;
import java.net.InetAddress;
import java.util.logging.Level;

import edu.biu.scapi.generals.Logging;

/** 
 * @author LabTest
 */
class SecuringConnectionThread extends Thread{
	private PlainChannel channel;
	private boolean bStopped = false;
	private boolean doConnect;
	private InetAddress ipAddres;
	private int port;
	KeyExchangeProtocol keyExchangeProtocol;
	KeyExchangeOutput keyExchangeOutput;
	
	/** 
	 * @param channel
	 * @param IP
	 * @param port
	 * @param doConnect
	 */
	SecuringConnectionThread(PlainChannel channel, InetAddress IP, int port,
			boolean doConnect, KeyExchangeProtocol keyExchangeProtocol, KeyExchangeOutput keyExchangeOutput) {

		setName("SecuringConnection-" + getName());
		this.doConnect = doConnect;
		this.channel = channel;
		this.ipAddres = IP;
		this.port = port;
		this.keyExchangeProtocol = keyExchangeProtocol;
		this.keyExchangeOutput = keyExchangeOutput;
		
	}
	
	/**
	 * 
	 * Sets the flag bStopped to false. In the run function of this thread this flag is checked
	 * 					if the flag is true the run functions returns, otherwise continues.
	 */
	void stopConnecting(){
		
		//set the flag to true.
		bStopped = true;
	}
	

	/**
	 * The main function of the thread. While thread has not been stopped by owner and connection has not been established and secured connect
	 * if the socket is not already connected. Then engage in a key exchange protocol and set the status of the channel accordingly.
	 */
	public void run() {

		//while thread has not been stopped by owner and connection has failed
		while(!bStopped && !channel.isConnected()){
					
			
			if(doConnect){
				channel.setState(PlainChannel.State.CONNECTING);
				
				Logging.getLogger().log(Level.INFO, "state: connecting " + channel.toString());

				try {
					//try to connect
					channel.connect();
					
				} catch (IOException e) {

					//e.printStackTrace();
										
				}
			}
		}
		
		if(!bStopped){
			
			
			//set channel state to securing
			channel.setState(PlainChannel.State.SECURING);
			
			Logging.getLogger().log(Level.INFO, "state: securing " + channel.toString());
			
			//start key exchange protocol
			keyExchangeProtocol.start(null);
			
			//set the output of the protocol with the keys
			KeyExchangeOutput localKeyExchangeOutput = (KeyExchangeOutput) keyExchangeProtocol.getOutput();
			
			//copy the key exchange output to the output that was passed to the object in the constructor
			keyExchangeOutput.setEncKey(localKeyExchangeOutput.getEncKey());
			keyExchangeOutput.setMacKey(localKeyExchangeOutput.getMacKey());
			
			//set the channel state to READY
			channel.setState(PlainChannel.State.READY);
			Logging.getLogger().log(Level.INFO, "state: ready " + channel.toString());
			
			
		}
		Logging.getLogger().log(Level.INFO, "End of securing thread run" + channel.toString());
	}


	/**
	 * @return the channel
	 */
	PlainChannel getChannel() {
		return channel;
	}
}
