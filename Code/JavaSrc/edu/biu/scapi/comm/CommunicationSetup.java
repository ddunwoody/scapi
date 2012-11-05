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
 * class CommunicationSetup:
 * 
 * An application requesting from CommunicationSetup to prepare for communication needs to provide the following information as input:
 *   •	The list of parties to connect to. As a convention, we will set the first party in the list to be the requesting party, that is, 
 * 		the party represented by the application. 
 *   •	The security level required. We assume the same security level for all connections for a given protocol. This may change.
 * 		We define four levels of security: a) plain, b) encrypted, c) authenticated d) encrypted and authenticated.
 *   •	Which type of connecting success is required.
 *   •	Which Key Exchange Protocol to use.
 *   •	What encryption and/or mac algorithm to use.
 *   •	A time-out specifying how long to wait for connections to be established and secured.
 * 
 * CommunicationSetup implements the org.apache.commons.exec.TimeoutObserver interface. 
 * This interface supplies a mechanism for notifying classes that a timeout has arrived. 
 */

package edu.biu.scapi.comm;


import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.InvalidKeyException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Vector;
import java.util.logging.Level;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.exec.TimeoutObserver;
import org.apache.commons.exec.Watchdog;

import edu.biu.scapi.exceptions.DuplicatePartyException;
import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.generals.Logging;
import edu.biu.scapi.midLayer.symmetricCrypto.encryption.SymmetricEnc;
import edu.biu.scapi.midLayer.symmetricCrypto.mac.Mac;
import edu.biu.scapi.tools.Factories.MacFactory;
import edu.biu.scapi.tools.Factories.SymmetricEncFactory;





public class CommunicationSetup implements TimeoutObserver{
	private boolean bTimedOut = false;
	private boolean enableNagle = false;
	private List<Party> partiesList;
	private EstablishedConnections establishedConnections;
	private KeyExchangeProtocol keyExchangeProtocol;
	private ConnectivitySuccessVerifier connectivitySuccessVerifier;
	private SecurityLevel securityLevel;
	private ListeningThread listeningThread;
	private Vector<SecuringConnectionThread> threadsVector;
	private Map<InetSocketAddress,KeyExchangeOutput> keyExchangeMap;
	
	
	
	
	/**
	 * 
	 */
	public CommunicationSetup() {
		
		
	}

	/** 
	 * The main function of the class. This function is also the only public function in the class. An application that wants to use
	 * the communication layer will call this function in order to prepare for communication after providing the required parameters. 
	 * This function initiates the creation of the final actual socket connections between the parties. If this function succeeds, the 
	 * application may use the send and receive functions of the created channels to pass messages.
	 * @param listOfParties the original list of parties to connect to
	 * @param keyExchange the key exchange algorithm protocol to use after a channel is connected
	 * @param securityLevel the required security level for all the connections. E.g Plain, encrypted, authenticated or secured
	 * @param successLevel the ConnectivitySuccessVerifier algorithm to use
	 * @param timeOut the maximum amount of time we allow for the connection stage
	 * @return true if the success function has succeeded and false otherwise
	 */
	//We should also allow the user to choose the Mac algorithm and Encryption Scheme if needed together with the security level
	public Map<InetSocketAddress, Channel> prepareForCommunication(List<Party> listOfParties,
			KeyExchangeProtocol keyExchange, SecurityLevel securityLevel,
			ConnectivitySuccessVerifier successLevel, long timeOut) {
		
		
		//set parameters
		partiesList = listOfParties;
		keyExchangeProtocol = keyExchange;
		this.securityLevel = securityLevel;
		connectivitySuccessVerifier = successLevel;
		
		establishedConnections = new EstablishedConnections();
		
		//initialize the threadVector and the map of the key exchange outputs
		threadsVector = new Vector<SecuringConnectionThread>();
		keyExchangeMap = new HashMap<InetSocketAddress,KeyExchangeOutput>();
		
		//start the watch dog with timeout
		Watchdog watchdog = new Watchdog(timeOut);
		//add this instance as the observer in order to receive the event of time out.
		watchdog.addTimeoutObserver(this);
		
		watchdog.start();
		
		Logging.getLogger().log(Level.WARNING,"Testing log");
		
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
			return null;
		}
		
		//remove all connections with not READY state
		establishedConnections.removeNotReadyConnections();
		
		//set nagle algorithm
		establishedConnections.enableNagle(enableNagle);
		
		//update the security level for each connection
		setSecurityLevel();
		
		//return the map of channels held in the established connection object.
		return establishedConnections.getConnections();
		
	}
	
	/**
	 * 
	 * Does the same as the other prepareForCommunication function only sets the flag of enableNagle first.
	 * 
	 * @param enableNagle a flag indicating weather or not to use the nagle optimization algorithm 
	 * @return
	 */
	public Map<InetSocketAddress, Channel> prepareForCommunication(List<Party> listOfParties,
			KeyExchangeProtocol keyExchange, SecurityLevel securityLevel,
			ConnectivitySuccessVerifier successLevel, long timeOut, boolean enableNagle) {
		
		this.enableNagle = enableNagle;
		
		return prepareForCommunication(listOfParties, keyExchange, securityLevel, successLevel, timeOut);
	}


	/**
	 * 
	 * Using the SecuringConnectionThread and the ListeningThread we connect the parties via sockets.
	 * 								   We either connect by initiating a connection or by listening to incoming connection requests.
	 * @throws DuplicatePartyException This exception is for the case where there are two parties in the list of parties with the same ip+port
	 */
	private void establishAndSecureConnections() throws DuplicatePartyException {
		
		//Create an iterator to go over the list of parties 
		Iterator<Party> itr = partiesList.iterator();
		Party firstParty = null;
		Party party;
		int numOfIncomingConnections = 0;
		
		//temp map
		Map<InetAddress, Vector<SecuringConnectionThread>> ListeningThreadMap = new HashMap<InetAddress, Vector<SecuringConnectionThread>>();
		
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
						numOfIncomingConnections, ListeningThreadMap,
						channel, keyExchangeOutput);
				
			}
		}
		
		if(ListeningThreadMap.size()>0){//there are down connections need to listen to connections using the listeningThread
			//send information to the listening thread
			listeningThread = new ListeningThread(ListeningThreadMap, firstParty.getPort(), numOfIncomingConnections);
			listeningThread.start();
		}
		
	}

	/**
	 * 
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
	 * 
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
	 *  
	 * This function goal is to serve as a barrier. It is called from the prepareForCommunication function. The idea
	 * 							is to let all the threads finish running before proceeding. 
	 */ 
	private void verifyConnectingStatus() {

		//while the thread has not been stopped and not all the channels are connected
		while(!bTimedOut && !establishedConnections.areAllConnected()){
			try {
				Thread.sleep(500);
			} catch (InterruptedException e) {

				Logging.getLogger().log(Level.FINEST, e.toString());
			}
		}
	}

	/** 
	 * 
	 * Runs the success algorithm. 
	 * @return true if the connections in the connections in the establishedConnections and possibly connections of the other parties 
	 * 			 has succeeded in terms of the success algorithm. Otherwise, false. If the success has failed all the connections of the 
	 * 			 establishedConnections are removed
	 */
	private boolean runSuccessAlgo() {

		//call the relevant success algorithm
		return connectivitySuccessVerifier.hasSucceded(establishedConnections, partiesList);
	}

	/**
	 * 
	 * In this function we decorate the channels to suit the requested security level. If the required security level
	 * 					  is plain, no decoration is needed. For authenticated we decorate the channel by an authenticated channel. for encrypted, we 
	 * 					  decorate with encrypted channel. For secured, we decorated with both authenticated and encrypted channel.
	 * 
	 *  Note:			  The decorated channel has a different pointer in memory, thus we need to put the newly decorated channel in the map
	 *  				  and removing the plain channel from the map. Since we iterate on the map, we cannot remove and add in the middle of 
	 *  				  iteration ( we would get the ConcurrentModificationException exception) and thus we create a temporary map with the decorated channels and at the end clear the map and add all
	 *  				  the decorated channels.
	 */
	@SuppressWarnings("unused")
	private void setSecurityLevel() {
		
		//For the moment the only security level supported is PLAIN. Therefore,return immediately from this function without
		//performing the necessary tasks to provide the channel with higher levels of security.
		//As soon as we finish implementing the EncryptedChannel and the AuthenticatedChannel, this return statement should be removed.
		if (true)
			return;
		
		if(securityLevel==SecurityLevel.PLAIN)//If it is plain there is nothing to decorate
			return;
		else{//Set the security level only if the security level is not plain. 
			
			//create a temp map since if we change the main map in the middle of iterations we will get the exception ConcurrentModificationException 
			Map<InetSocketAddress,Channel> tempConnectionsMap = new HashMap<InetSocketAddress,Channel>();  
			
		
			InetSocketAddress localInetSocketAddress = null;
			Set<InetSocketAddress> set = establishedConnections.getConnections().keySet();
	
			//go over the addresses of the established connections map
		    Iterator<InetSocketAddress> itr = set.iterator();
		    while (itr.hasNext()) {
		    	
		    	//get the channel's address
		    	localInetSocketAddress = itr.next();
		    	
		    	//get the channel from the collection
		    	Channel ch = establishedConnections.getConnection(localInetSocketAddress);
		    	
		    	//remove the channel and save it for decoration
		    	//Channel ch = establishedConnections.removeConnection(localInetSocketAddress);
		    	
		    	//get the keyExchange output
		    	KeyExchangeOutput keyExchangeOutput = keyExchangeMap.get(localInetSocketAddress) ;
		    	
		    	//decorate the channel
		    	switch(securityLevel){
		    		case ENCRYPTED :{
		    			
		    			//create an encrypted channel
		    			//For now we are going to hard-code the Encryption Scheme being used, but we should allow the external user to choose it.
		    			SymmetricEnc aesEnc = null;
						try {
							aesEnc = SymmetricEncFactory.getInstance().getObject("CBCEncRandomIV");
						} catch (FactoriesException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
						byte[] fixedKey = new byte[]{7, -126, 83, -82, 68, 67, -46, -58, 70, 123, -127, -66, -4, 37, -1, 15};
					SecretKey key = new SecretKeySpec(fixedKey,"AES" );
					try {
						aesEnc.setKey(key);
					} catch (InvalidKeyException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
		    			EncryptedChannel encChannel = new EncryptedChannel(ch, aesEnc);
		    			//establishedConnections.addConnection(encChannel, localInetSocketAddress);
		    			tempConnectionsMap.put(localInetSocketAddress,encChannel);
		    			break;
		    		}
		    		case AUTHENTICATED : {
		    			
		    			//create an authenticated channel
		    			//For now we are going to hard-code the MAC algorithm being used, but we should allow the external user to choose it.
		    			Mac mac = null;
						try {
							mac = MacFactory.getInstance().getObject("CBCMacPrepending");
						} catch (FactoriesException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
		    			//SecretKey key = mac.generateKey(128);
		    			//byte[] keyRep = key.getEncoded();
		    			//for(int i = 0 ; i < keyRep.length; i++)
		    			//	System.out.println(keyRep[i]);
						byte[] fixedKey = new byte[]{-82, 123, 72, -83, 92, 100, -17, 51, -34, -49, 59, 112, 122, 5, -116, 32};
						SecretKey key = new SecretKeySpec(fixedKey,"AES" );
						
						
						try {
							mac.setKey(key);
						} catch (InvalidKeyException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
		    			AuthenticatedChannel authenChannel = new AuthenticatedChannel(ch, mac);
		    			//establishedConnections.addConnection(authenChannel, localInetSocketAddress);
		    			tempConnectionsMap.put(localInetSocketAddress, authenChannel);
		    			break;
		    		}
		    		case SECURE : {
		    			
		    			//decorate with authentication and then with encryption - order is important for security
		    			//For now we are going to hard-code the MAC algorithm and Encryption Scheme being used, but we should allow the external user to choose it.
		    			Mac mac = null;
						try {
							mac = MacFactory.getInstance().getObject("CBCMac");
						} catch (FactoriesException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
		    			SecretKey keyMac = mac.generateKey(64);
		    			try {
							mac.setKey(keyMac);
						} catch (InvalidKeyException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
		    			AuthenticatedChannel authenChannel = new AuthenticatedChannel(ch, mac);
		    			
		    			SymmetricEnc aesEnc = null;
						try {
							aesEnc = SymmetricEncFactory.getInstance().getObject("CBCEncRandomIV");
						} catch (FactoriesException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
		    			SecretKey keyEnc = aesEnc.generateKey(128);
		    			try {
							aesEnc.setKey(keyEnc);
						} catch (InvalidKeyException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
		    			EncryptedChannel secureChannel = new EncryptedChannel(authenChannel, aesEnc);
		    			
		    			//establishedConnections.addConnection(secureChannel, localInetSocketAddress);
		    			tempConnectionsMap.put(localInetSocketAddress, secureChannel);
		    			break;
		    			
		    		}
		    	}		    		
		    }
		    
		    establishedConnections.getConnections().clear();
		    establishedConnections.getConnections().putAll(tempConnectionsMap);
		}	
	}

	/**
	 * An event called if the timeout has passed. This is called by the infrastructure of the watchdog and the fact that
	 * 					this class is also an observer.
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
	
	public Map<InetSocketAddress, Channel> getConnections(){
		return establishedConnections.getConnections();
		
	}
}
