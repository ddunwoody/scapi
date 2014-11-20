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


import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Vector;
import java.util.logging.Level;

import org.apache.commons.exec.TimeoutObserver;
import org.apache.commons.exec.Watchdog;

import edu.biu.scapi.exceptions.DuplicatePartyException;
import edu.biu.scapi.generals.Logging;



/** 
 * The CommunicationSetup class is the heart of the Communications Layer. The Communications Layer package is a tool used by a client that is interested in setting up connections 
 * between itself and other parties. As such, this layer does not initiate any independent tasks, but the opposite. Given a list of parties, it attempts to set connections to them 
 * according to parameters given by the calling application. If succeeds, it returns these connections so that the calling client can send and receive data over them.<p>
 * An application written for running an MPC protocol can be the client of the Communications Layer. An example of a possible usage follows:<p>
 * <ul>
 * <li>Instantiate an object of type CommunicationSetup.</li>
 * <li>Call the prepareForCommunication method of that object with a list of parties to connect to and other setup parameters. (prepareForCommunication is the only public method of this class).</li>
 * <li>Get from prepareForCommunication a container holding all ready connections.</li>
 * <li>Start the MPC protocol.</li> 
 * <li>Call the send and receive methods of the ready connections as needed by the MPC.</li>
 * </ul>
 * The application may be interested in putting each connection in a different thread but it is up to the application to do so and not the responsibility of the Communications Layer. This provides more flexibility of use.
 * The Communications Layer encapsulates the stage of connecting to other parties. In actuality, the connection to other parties is performed in a few steps, which are not visible to the outside user.
 * These steps are:<p>
 * <ul> 
 * <li>create an actual TCP connection with each party</li>
 * <li>exchange keys between my party and other parties</li>
 * <li>run a protocol that checks (for different types of required success) if all the necessary connections were set between my party and other parties.</li>
 * </ul>
 * In the end, the Communications Layer via the CommunicationSetup class returns to the calling application, a set of connected and ready channels to be used throughout a cryptographic protocol.<br/>
 * From this point onwards, the application can send and receive messages in each connection as required by the protocol.<p>
 * CommunicationSetup implements the org.apache.commons.exec.TimeoutObserver interface. 
 * This interface supplies a mechanism for notifying classes that a timeout has arrived. 
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University
 */

public class CommunicationSetup implements TimeoutObserver{
	private boolean bTimedOut = false;
	private boolean enableNagle = false;
	private List<Party> partiesList;
	private EstablishedConnections establishedConnections;
	private KeyExchangeProtocol keyExchangeProtocol;
	private ConnectivitySuccessVerifier connectivitySuccessVerifier;
	private ListeningThread listeningThread;
	private Vector<SecuringConnectionThread> threadsVector;
	private Map<InetSocketAddress,KeyExchangeOutput> keyExchangeMap;
	private Watchdog watchdog;
	
	
	
	/**
	 * Create a CommunicationSetup instance which is the heart of the Communication Layer. 
	 */
	public CommunicationSetup() {
		
		
	}
	
	/**  
	 * This function is package private and is called by the public prepareFunctions. It requests a KeyExchangeProtocol that has not been implemented yet.
	 * It initiates the creation of the final actual socket connections between the parties. If this function succeeds, the 
	 * application may use the send and receive functions of the created channels to pass messages.
	 * 
	 * @param listOfParties the original list of parties to connect to. As a convention, we will set the <B>first party</B> in the list to be the <B>requesting party</B>, that is, 
	 * 	 					the party represented by the application.
	 * @param keyExchange the key exchange algorithm protocol to use after a channel is connected
	 * @param successLevel the ConnectivitySuccessVerifier algorithm to use
	 * @param timeOut the maximum amount of time we allow for the connection stage
	 * @return a set of connected and ready channels to be used by the parties to send and receive data, it may be null if none succeeded
	 */
	Map<InetSocketAddress, Channel> prepareForCommunication(List<Party> listOfParties, KeyExchangeProtocol keyExchange,	ConnectivitySuccessVerifier successLevel, long timeOut) {		
		//set parameters
		partiesList = listOfParties;
		keyExchangeProtocol = keyExchange;
		connectivitySuccessVerifier = successLevel;
		
		establishedConnections = new EstablishedConnections();
		
		//initialize the threadVector and the map of the key exchange outputs
		threadsVector = new Vector<SecuringConnectionThread>();
		keyExchangeMap = new HashMap<InetSocketAddress,KeyExchangeOutput>();
		
		//start the watch dog with timeout
		watchdog = new Watchdog(timeOut);
		//add this instance as the observer in order to receive the event of time out.
		watchdog.addTimeoutObserver(this);
		
		watchdog.start();
		
		//establish connections.
		try {
			establishAndSecureConnections();
		} catch (DuplicatePartyException e) {
			
			Logging.getLogger().log(Level.SEVERE, e.toString() );
		}
		
		//verify connection
		verifyConnectingStatus();
		
		//run success function
		if(!runSuccessAlgo()){
			//remove connections from the list of established connections
			//Eventually, when different ConnectivitySuccessVerifiers are implemented there might be an impact what happens to the connections that did succeed.
			//For example, assume that only 80% of the connections requested were established but the ConnectivitySuccessVerifier specified requires 100%. Then, obviously
			//the function didn't succeed and null should be returned. However, it would be a pity to let go (delete and remove) the 80% of connections that did succeed.
			//It may be possible (and this will depend on the requirements of the ConnectivitySuccessVerifier) to keep the already established connections and only try 
			//to establish what is missing. In some other cases it will be necessary to start everything over form the beginning. As a conclusion, this is left for future implementation.
			return null;
		}
		
		//remove all connections with not READY state
		establishedConnections.removeNotReadyConnections();
		
		//set nagle algorithm
		establishedConnections.enableNagle(enableNagle);
		
		//update the security level for each connection
		//setSecurityLevel();
		
		//return the map of channels held in the established connection object.
		return establishedConnections.getConnections();
		
	}
	
	/**
	 * This function is package private and is called by the public prepareFunctions. It requests a KeyExchangeProtocol that has not been implemented yet.
	 * Does the same as the above prepareForCommunication function only sets the flag of enableNagle first.
	 * 
	 * @param enableNagle a flag indicating weather or not to use the Nagle optimization algorithm 
	 * @return a set of connected and ready channels to be used by the parties to send and receive data, it may be null if none succeeded
	 */
	Map<InetSocketAddress, Channel> prepareForCommunication(List<Party> listOfParties, KeyExchangeProtocol keyExchange, ConnectivitySuccessVerifier successLevel, 
															long timeOut, boolean enableNagle) {
		
		this.enableNagle = enableNagle;
		
		return prepareForCommunication(listOfParties, keyExchange, successLevel, timeOut);
	}

	/** 
	 * An application that wants to use the communication layer will call this function in order to prepare for communication after providing the required parameters. 
	 * This function initiates the creation of the final actual socket connections between the parties. If this function succeeds, the 
	 * application may use the send and receive functions of the created channels to pass messages.<p> 
	 * Note that using this function you can choose to use or not to use the Nagle algorithm.
	 * 
	 * @param listOfParties the original list of parties to connect to. As a convention, we will set the <B>first party</B> in the list to be the <B>requesting party</B>, that is, 
	 * 	 					the party represented by the application.
	 * @param successLevel the ConnectivitySuccessVerifier algorithm to use
	 * @param timeOut the maximum amount of time we allow for the connection stage
	 * @param enableNagle a flag indicating weather or not to use the Nagle optimization algorithm. For Cryptographic algorithms is better to have it disabled
	 * @return a set of connected and ready channels to be used by the parties to send and receive data, it may be null if none succeeded
	 */
	public Map<InetSocketAddress, Channel> prepareForCommunication(List<Party> listOfParties,ConnectivitySuccessVerifier successLevel, 
																	long timeOut, boolean enableNagle) {
				
		KeyExchangeProtocol keyExchange = new KeyExchangeProtocol();
		return prepareForCommunication(listOfParties, keyExchange, successLevel, timeOut, enableNagle);
	}
	
	/**
	 * An application that wants to use the communication layer will call this function in order to prepare for communication after providing the required parameters. 
	 * This function initiates the creation of the final actual socket connections between the parties. If this function succeeds, the 
	 * application may use the send and receive functions of the created channels to pass messages.<p> 
	 * In this function, Nagle’s algorithm is disabled; for cryptographic protocols this is typically much better.
	 *  
	 * @param listOfParties the original list of parties to connect to. As a convention, we will set the <B>first party</B> in the list to be the <B>requesting party</B>, that is, 
	 * 	 					the party represented by the application.
	 * @param successLevel the ConnectivitySuccessVerifier algorithm to use
	 * @param timeOut the maximum amount of time we allow for the connection stage
	 * @return a set of connected and ready channels to be used by the parties to send and receive data, it may be null if none succeeded
	 */
	public Map<InetSocketAddress, Channel> prepareForCommunication(List<Party> listOfParties,ConnectivitySuccessVerifier successLevel, long timeOut){
		KeyExchangeProtocol keyExchange = new KeyExchangeProtocol();
		return prepareForCommunication(listOfParties, keyExchange, successLevel, timeOut);
	}

	/**
	 * 
	 * Using the SecuringConnectionThread and the ListeningThread we connect the parties via sockets.
	 * We either connect by initiating a connection or by listening to incoming connection requests.
	 * @throws DuplicatePartyException This exception is for the case where there are two parties in the list of parties with the same ip+port
	 */
	private void establishAndSecureConnections() throws DuplicatePartyException {
		
		//Create an iterator to go over the list of parties 
		Iterator<Party> itr = partiesList.iterator();
		Party firstParty = null;
		Party party;
		int numOfIncomingConnections = 0;
		
		//temp map
		Map<InetAddress, Vector<SecuringConnectionThread>> listeningThreadMap = new HashMap<InetAddress, Vector<SecuringConnectionThread>>();
		
		//the first party is me. Other parties identity will be compared with this party
		if(itr.hasNext()){
			
			firstParty = itr.next();
		}
		
		//go over the elements of the list of parties
		while(itr.hasNext()){
			
			//get the next party in the list.
			party = itr.next();
			
			//create an InetSocketAddress
			InetSocketAddress inetSocketAdd = new InetSocketAddress(party.getIpAddress(), party.getPort());
			//create a channel for this party
			PlainChannel channel = new PlainTCPChannel(inetSocketAdd);
			//set to NOT_INIT state
			channel.setState(PlainChannel.State.NOT_INIT);
			//add to the established connection object
			establishedConnections.addConnection(inetSocketAdd, channel);
			
			//create a key exchange output to pass to the SecuringConnectionThread
			KeyExchangeOutput keyExchangeOutput = new KeyExchangeOutput();
			
			//add the key exchange output to the map
			keyExchangeMap.put(inetSocketAdd, keyExchangeOutput);
			
			
			int partyCompare = firstParty.compareTo(party);
			if(partyCompare==0){//should not happen since it means that there is another party in the list with the same ip+port
				throw new DuplicatePartyException("Another party with the same ip address and port");
			}
			//UPWARD connection
			else if(firstParty.compareTo(party)>0){
				
				upwardConnection(party, channel, keyExchangeOutput);
								
			}
			else{ //DOWN connection
				
				numOfIncomingConnections = downConnection(party,
						numOfIncomingConnections, listeningThreadMap,
						channel, keyExchangeOutput);
				
			}
		}
		
		if(listeningThreadMap.size()>0){//there are down connections need to listen to connections using the listeningThread
			//send information to the listening thread
			listeningThread = new ListeningThread(listeningThreadMap, firstParty, numOfIncomingConnections);
			listeningThread.start();
		}
		
	}

	/**
	 * Connect to a party with ID less than mine.
	 * @param party
	 * @param numOfIncomingConnections
	 * @param listeningThreadMap
	 * @param channel
	 * @param keyExchangeOutput
	 * @return
	 */
	private int downConnection(
			Party party,
			int numOfIncomingConnections,
			Map<InetAddress, Vector<SecuringConnectionThread>> listeningThreadMap,
			PlainChannel channel, KeyExchangeOutput keyExchangeOutput) {
		boolean doConnect;
		//increase the index of incoming connections
		numOfIncomingConnections++;
		
		//set doConnect to false. We do not want the thread to try to connect.
		doConnect = false;
		
		//create a new SecuringConnectionThread 
		SecuringConnectionThread scThread = new SecuringConnectionThread(channel, party.getIpAddress(), party.getPort(), doConnect , keyExchangeProtocol, keyExchangeOutput);
		
		//add to the thread vector
		threadsVector.add(scThread);
		
		//a vector holding the securing threads
		Vector<SecuringConnectionThread> vector; 
		if(listeningThreadMap.containsKey(party.getIpAddress())){
			//ip already exists insert to the vector
			vector = listeningThreadMap.get(party.getIpAddress());
			
			//add the thread to the existing vector
			vector.add(scThread);
		}
		else{//there is no such an ip. create a new vector 
			
			vector = new Vector<SecuringConnectionThread>();
			vector.add(scThread);
			
			//add thread to the local vector so the listening thread can start the securing thread.
			listeningThreadMap.put(party.getIpAddress(), vector);
			
		}
		return numOfIncomingConnections;
	}

	/**
	 * Connect to a party with ID more than mine.
	 * @param party
	 * @param channel
	 * @param keyExchangeOutput
	 */
	private void upwardConnection(Party party, PlainChannel channel,
			KeyExchangeOutput keyExchangeOutput) {
		boolean doConnect;
		//set doConnect to true. We need the thread to connect to the other side of the channel. 
		doConnect = true;
		
		//create a new SecuringConnectionThread 
		SecuringConnectionThread scThread = new SecuringConnectionThread(channel, party.getIpAddress(), party.getPort(), doConnect , keyExchangeProtocol, keyExchangeOutput);
		
		//add to the thread vector
		threadsVector.add(scThread);
		
		//start the thread
		scThread.start();
	}

	/** 
	 * This function serves as a barrier. It is called from the prepareForCommunication function. The idea
	 * is to let all the threads finish running before proceeding. 
	 */ 
	private void verifyConnectingStatus() {
		boolean allConnected = false;
		//while the thread has not been stopped and not all the channels are connected
		while(!bTimedOut && !(allConnected = establishedConnections.areAllConnected())){
			try {
				Thread.sleep(500);
			} catch (InterruptedException e) {

				Logging.getLogger().log(Level.FINEST, e.toString());
			}
		}
		//If we already know that all the connectios were established we can stop the watchdog.
		if(allConnected)
			watchdog.stop();
	}

	/** 
	 * 
	 * Runs the success algorithm. 
	 * @return true if the level of connectivity specified by the {@link ConnectivitySuccessVerifier} was reached 
	 * 		   false otherwise
	 */
	private boolean runSuccessAlgo() {

		//call the relevant success algorithm
		return connectivitySuccessVerifier.hasSucceded(establishedConnections, partiesList);
	}
	
	/**
	 * This function is called by the infrastructure of the Watchdog if the previously set timeout has passed. (Do not call this function).
	 */
	public void timeoutOccured(Watchdog w) {

		Logging.getLogger().log(Level.INFO, "Timeout occured");
		
		//timeout has passed set the flag
		bTimedOut = true;
		
		//stop all threads in the vector and the listening thread
		for(int i=0; i< threadsVector.size(); i++){
			
			//get a thread from the vector of threads
			SecuringConnectionThread thread = threadsVector.elementAt(i);
			
			//sets the flag of the thread to stopped. This will make the run function of the thread to terminate if it has not finished yet.
			thread.stopConnecting();
			
		}	
		
		//further stop the listening thread if it still runs. Similarly, it sets the flag of the listening thread to stopped.
		if(listeningThread!=null)
			listeningThread.stopConnecting();
	}
	
}
