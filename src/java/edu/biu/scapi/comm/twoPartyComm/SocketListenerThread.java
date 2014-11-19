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

package edu.biu.scapi.comm.twoPartyComm;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.util.logging.Level;
import edu.biu.scapi.generals.Logging;

/**
 * This class listen to incoming connections from the other party and set the received sockets to the channels.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
class SocketListenerThread extends Thread{
	
	protected InetAddress partyAddr;				//The address of the other party.
	protected PlainTCPSocketChannel[] channels;	//All connections between me and the other party. The received sockets of each channel should be set when accepted. 
	
	protected boolean bStopped = false;			//A flag that indicates if to keep on listening or stop.
	protected ServerSocket listener;		//Channel to listen on.


	/**
	* A constructor that open the server socket.
	* @param channels the channels that should be set with receive socket.
	* @param me the data of the current application.
	* @param partyAdd The address to listen on.
	*/
	public SocketListenerThread(PlainTCPSocketChannel[] channels, SocketPartyData me, InetAddress partyAdd) {
	
		this.channels = channels;
		this.partyAddr = partyAdd;
		
		CreateServerSocket(me);
	}


	protected void CreateServerSocket(SocketPartyData me) {
		//prepare the listener.
		try {
			ServerSocketChannel channel = ServerSocketChannel.open();
			channel.configureBlocking (false);
			listener = channel.socket();
			listener.bind (new InetSocketAddress (me.getIpAddress(), me.getPort()));
		} catch (IOException e) {
		
			Logging.getLogger().log(Level.WARNING, e.toString());
	
		}
	}


	/**
	* Sets the flag bStopped to false. In the run function of this thread this flag is checked - 
	* if the flag is true the run functions returns, otherwise continues.
	*/
	public void stopConnecting(){
	
		//Set the flag to true.
		bStopped = true;
	}



	/**
	* This function is the main function of the SocketListenerThread. Mainly, we listen and accept valid connections 
	* as long as the flag bStopped is false or until we have got as much connections as we should.<p>
	* We use the ServerSocketChannel rather than the regular ServerSocket since we want the accept to be non-blocking. 
	* If the accept function is blocking the flag bStopped will not be checked until the thread is unblocked.  
	*/
	public void run() {
	
		//Set the state of all channels to connecting.
		int size = channels.length;
		for (int i=0; i<size; i++){
		
			channels[i].setState(PlainTCPSocketChannel.State.CONNECTING);
		}
		
		int i=0;
		//Loop for listening to incoming connections and make sure that this thread should not stopped.
		while (i < size && !bStopped) {
		
			SocketChannel socketChannel = null;
			try {
			
				//Use the server socket to listen to incoming connections.
				Logging.getLogger().log(Level.INFO, "Trying to listen "+ listener.getLocalPort());
				
				socketChannel = listener.getChannel().accept();
			
			}	catch (ClosedChannelException e) {
				// TODO: handle exception
				Logging.getLogger().log(Level.WARNING, e.toString());
			} 	catch (IOException e) {
			
				Logging.getLogger().log(Level.WARNING, e.toString());
			}
		
			//If there was no connection request wait a second and try again.
			if(socketChannel==null){
				try {
					Thread.sleep (1000);
				} catch (InterruptedException e) {
				
					Logging.getLogger().log(Level.INFO, e.toString());
				}
			//If there was an incoming request, check it.
			} else{
				//Get the ip of the client socket.
				InetAddress inetAddr = socketChannel.socket().getInetAddress();
				
				//if the accepted address is not a valid address. I.e. different from the other party's address. 
				if(!inetAddr.equals(partyAddr)){//an unauthorized ip tried to connect
				
					//Close the socket.
					try {
						socketChannel.close();
					} catch (IOException e) {
					
						Logging.getLogger().log(Level.WARNING, e.toString());
					}
				//If the accepted address is valid, set it as the receive socket of the channel.
				//The send socket is set in the SocketCommunicationSetup.connect function. 
				} else{ 
					channels[i].setReceiveSocket(socketChannel.socket());
					
					//Increment the index of incoming connections.
					i++;
				}
			}
		}
	
		Logging.getLogger().log(Level.INFO, "End of listening thread run");
		
		//After accepting all connections, close the thread.
		try {
			listener.close();
			} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	
	}
}
