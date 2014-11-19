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

import java.net.InetSocketAddress;
import java.util.Map;
import java.util.logging.Level;

import org.apache.commons.exec.TimeoutObserver;
import org.apache.commons.exec.Watchdog;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.DuplicatePartyException;
import edu.biu.scapi.generals.Logging;

/**
 * This class implements a communication between two parties using TCP sockets.<p>
 * Each created channel contains two sockets; one is used to send messages and one to receive messages.<p>
 * This class encapsulates the stage of connecting to other parties. In actuality, the connection to other parties is 
 * performed in a few steps, which are not visible to the outside user.
 * These steps are:<p>
 * <ul> 
 * <li>for each requested channel,</li>
 * <li>Create an actual TCP socket with the other party. This socket is used to send messages</li>
 * <li>Create a server socket that listen to the other party's call. When received, the created socket is used to receive messages from the other party.</li>
 * <li>run a protocol that checks if all the necessary connections were set between my party and other party.</li>
 * <li>In the end return to the calling application a set of connected and ready channels to be used throughout a cryptographic protocol.</li>
 * </ul>
 * From this point onwards, the application can send and receive messages in each connection as required by the protocol.<p>
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class SocketCommunicationSetup implements TwoPartyCommunicationSetup, TimeoutObserver{

	protected boolean bTimedOut = false; 								//Indicated whether or not to end the communication.
	private Watchdog watchdog;										//Used to measure times.
	private boolean enableNagle = false;							//Indicated whether or not to use Nagle optimization algorithm.
	protected EstablishedSocketConnections establishedConnections;	//Holds the created channels.
	protected SocketListenerThread listeningThread;					//Listen to calls from the other party.
	private int connectionsNumber;									//Holds the number of created connections. 
	SocketPartyData me;												//The data of the current application
	SocketPartyData other;											//The data of the other application to communicate with.
	
	/**
	 * A constructor that set the given parties.
	 * @param me The data of the current application.
	 * @param party The data of the other application to communicate with.
	 * @throws DuplicatePartyException 
	 */
	public SocketCommunicationSetup(PartyData me, PartyData party) throws DuplicatePartyException{
		//Both parties should be instances of SocketPArty.
		if (!(me instanceof SocketPartyData) || !(party instanceof SocketPartyData)){
			throw new IllegalArgumentException("both parties should be instances of SocketParty");
		}
		this.me = (SocketPartyData) me;
		this.other = (SocketPartyData) party;
		
		//Compare the two given parties. If they are the same, throw exception.
		int partyCompare = this.me.compareTo(other);
		if(partyCompare == 0){
			throw new DuplicatePartyException("Another party with the same ip address and port");
		}
		connectionsNumber = 0;
	}
	
	/**  
	 * Initiates the creation of the actual sockets connections between the parties. If this function succeeds, the 
	 * application may use the send and receive functions of the created channels to pass messages.
	 * 
	 */
	@Override
	public Map<String, Channel> prepareForCommunication(String[] connectionsIds, long timeOut) {		
		
		//Start the watch dog with the given timeout.
		watchdog = new Watchdog(timeOut);
		//Add this instance as the observer in order to receive the event of time out.
		watchdog.addTimeoutObserver(this);
		watchdog.start();
		
		establishedConnections = new EstablishedSocketConnections();
		
		//Establish connections.
		establishAndSecureConnections(connectionsIds);
		
		//Verify connections.
		verifyConnectingStatus();
		
		//Remove all connections with not READY state.
		establishedConnections.removeNotReadyConnections();
		
		//Set Nagle algorithm.
		establishedConnections.enableNagle(enableNagle);
		
		//Update the number of the created connections.
		connectionsNumber += establishedConnections.getConnectionsCount();
		
		//Return the map of channels held in the established connection object.
		return establishedConnections.getConnections();
		
	}
	
	@Override
	public Map<String, Channel> prepareForCommunication(int connectionsNum, long timeOut) {
		//Prepare the connections Ids using the default implementation, meaning the connections are numbered 
		//according to their index. i.e the first connection's name is "1", the second is "2" and so on.
		String[] names = new String[connectionsNum];
		for (int i=0; i<connectionsNum; i++){
			names[i] = Integer.toString(connectionsNumber++);
		}
		
		//Call the other prepareForCommunication function with the created ids.
		return prepareForCommunication(names, timeOut);
	}

	/**
	 * This function does the actual creation of the communication between the parties.<p>
	 * A connected channel between two parties has two sockets. One is used by P1 to send messages and p2 receives them,
	 * while the other used by P2 to send messages and P1 receives them.
	 * 
	 * The function does the following steps:
	 * 1. Creates a channel for each connection
	 * 2. Start a listening thread that accepts calls from the other party.
	 * 3. Calls each channel's connect function in order to connect each channel to the other party.
	 * @param connectionsIds The names of the requested connections. 
	 *
	 */
	protected void establishAndSecureConnections(String[] connectionsIds) {
		
		//Create an InetSocketAddress of the other party.
		InetSocketAddress inetSocketAdd = new InetSocketAddress(other.getIpAddress(), other.getPort());
		
		int size = connectionsIds.length;
		//Create an array to hold the created channels.
		PlainTCPSocketChannel[] channels = new PlainTCPSocketChannel[size];
		
		//Create the number of channels as requested.
		for (int i=0; i<size; i++){
			//Create a channel.
			channels[i] = new PlainTCPSocketChannel(inetSocketAdd);
			//Set to NOT_INIT state.
			channels[i].setState(PlainTCPSocketChannel.State.NOT_INIT);
			//Add to the established connection object.
			establishedConnections.addConnection(connectionsIds[i], channels[i]);
		}
		
		//Create a listening thread with the created channels.
		//The listening thread receives calls from the other party and set the creates sockets as the receiveSocket of the channels.
		listeningThread = new SocketListenerThread(channels, me, other.getIpAddress());
		listeningThread.start();
		
		//Start the connections between me to the other party.
		connect(channels);
		
	}
	
	/**
	 * This function calls each channel to connect to the other party.
	 * @param channels between me to the other party.
	 */
	private void connect(PlainTCPSocketChannel[] channels){

		//For each channel, call the connect function until the channel is actually connected.
		for (int i=0; i<channels.length; i++){
			
			//while connection has not been stopped by owner and connection has failed.
			while(!channels[i].isSendConnected() && !bTimedOut){
				
				//Set the state to connecting.
				channels[i].setState(PlainTCPSocketChannel.State.CONNECTING);
				Logging.getLogger().log(Level.INFO, "state: connecting " + channels[i].toString());
				
				//Try to connect.
				channels[i].connect();
				
			}
				
			Logging.getLogger().log(Level.INFO, "End of securing thread run" + channels[i].toString());
		}
	}

	/** 
	 * This function serves as a barrier. It is called from the prepareForCommunication function. The idea
	 * is to let all the threads finish running before proceeding. 
	 */ 
	private void verifyConnectingStatus() {
		
		boolean allConnected = false;
		
		//Wait until the thread has been stopped or all the channels are connected.
		while(!bTimedOut && !(allConnected = establishedConnections.areAllConnected())){
			try {
				Thread.sleep(500);
			} catch (InterruptedException e) {

				Logging.getLogger().log(Level.FINEST, e.toString());
			}
		}
		
		//If we already know that all the connections were established we can stop the watchdog.
		if(allConnected){
			watchdog.stop();
		}
	}
	
	public void enableNagle(){
		//Set to true the boolean indicates whether or not to use the Nagle optimization algorithm. 
		//For Cryptographic algorithms is better to have it disabled.
		this.enableNagle  = true;
	}
	
	/**
	 * This function is called by the infrastructure of the Watchdog if the previously set timeout has passed. (Do not call this function).
	 */
	public void timeoutOccured(Watchdog w) {

		Logging.getLogger().log(Level.INFO, "Timeout occured");
		
		//Timeout has passed, set the flag.
		bTimedOut = true;
		
		//Further stop the listening thread if it still runs. Similarly, it sets the flag of the listening thread to stopped.
		if(listeningThread != null)
			listeningThread.stopConnecting();
	}

	/**
	 * This implementation has nothing to close besides the sockets (which are being closed by the channel instances).
	 */
	public void close() {}

}
