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

import java.net.InetSocketAddress;
import java.net.SocketException;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.logging.Level;

import edu.biu.scapi.exceptions.InvalidChannelException;
import edu.biu.scapi.generals.Logging;


/** 
 * 
 * The CommunicationSetup class holds a container of type EstablishedConnections that keeps track of the connections (channels) 
 * as they are being established. This container has a number of channels that can be in different states.
 * EstablishedConnections has regular operations of containers such as add and remove. It also has logical operations such as areAllConnected.
 * At the end of the “prepare for communication” method, the calling application receives a map of connections in the EstablishedConnections 
 * object held by the CommunicationSetup. At this stage, all the channels in EstablishedConnections object need to be in READY state. 
 * It is possible that this object will be null if the “prepare for communication” did not succeed. 
 * The key to the map is an object of type InetSocketAddress that holds the IP and the port. Since the IP and port are unique, 
 * they define a unique InetSocketAddress that can serve as a key to the map.   

 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
  */
class EstablishedConnections {
	private Map<InetSocketAddress,Channel> connectionsMap;

	
	/**
	 * 
	 */
	EstablishedConnections() {
		//initiate the map
		connectionsMap = new HashMap<InetSocketAddress,Channel>();
	}
	


	/**
	 * @return the connections
	 */
	Map<InetSocketAddress,Channel> getConnections() {
		return connectionsMap;
	}
	
	/** 
	 * Adds a channel with the address key to the map
	 * @param connection the value/channel to insert to the map
	 * @param address the key in the map
	 */
	void addConnection(InetSocketAddress address, Channel connection) {

		// add the channel to the map
		connectionsMap.put(address, connection);
	}

	/** 
	 * Removes a channel from the map.
	 * @param address the key of the channel in the map
	 */
	Channel removeConnection(InetSocketAddress address) {
		
		//remove the connection
		return connectionsMap.remove(address);
	}

	/** 
	 * Gets a channel from the map.
	 * @param address the key of the channel in the map
	 */
	Channel getConnection(InetSocketAddress address) {
		
		//remove the connection
		return connectionsMap.get(address);
	}

	
	/** 
	 * @return the number of channels in the map
	 */
	int getConnectionsCount() {
		
		return connectionsMap.size();
	}

	/** 
	 * @return true if all the channels are in READY state, false otherwise
	 */
	boolean areAllConnected() {

		//set an iterator for the connection map.
		Collection<Channel> c = connectionsMap.values();
		Iterator<Channel> itr = c.iterator();
		
		PlainChannel plainChannel;
		//go over the map and check if all the connections are in READY state
		while(itr.hasNext()){
			plainChannel = (PlainChannel)itr.next();
		       if(plainChannel.getState()!=PlainChannel.State.READY){
		    	   return false;
		       }
		}
		
		return true;
	}

	/** 
	 * Updates a channel state to a new state
	 * @param address the key in the map
	 * @param state the state of the channel to update to.
	 * @throws InvalidChannel 
	 */
	void updateConnectionState(InetSocketAddress address, PlainChannel.State state) throws InvalidChannelException {

		//get the channel from the map
		Channel channel = connectionsMap.get(address);
		
		if(channel instanceof PlainChannel){
			PlainChannel plainChannel = (PlainChannel)channel;
		
			plainChannel.setState(state);
		}
		else
			throw new InvalidChannelException("The related channel must be a plain channel");
	}
	
	/**
	 * 
	 * Removes all the connections which are not in READY state.
	 * 
	 * Note						 : The connection can be removed only by the iterator and not directly through the map. Otherwise an exception
	 * 							   will be thrown.
	 */
	void removeNotReadyConnections(){
		
		PlainChannel plainChannel;
		InetSocketAddress address;
			
		//set an iterator for the connection map.
		Iterator<InetSocketAddress> iterator = connectionsMap.keySet().iterator();
		
		//go over the map and check if all the connections are in READY state
		while(iterator.hasNext()){ 
			address = iterator.next();
			plainChannel = (PlainChannel) connectionsMap.get(address);
		       if(plainChannel.getState()!=PlainChannel.State.READY){

		    	   iterator.remove();
		    	   
		       }
		}
		
	}
	
	/**
	 * 
	 * @param enableNagle true for enabling nagle, otherwise false
	 */
	void enableNagle(boolean enableNagle){
		
		PlainTCPChannel plainTCPChannel;
		Channel channel;
		InetSocketAddress address;
		
		
		//set an iterator for the connection map.
		Iterator<InetSocketAddress> iterator = connectionsMap.keySet().iterator();
		
		//go over the map and check if all the connections are in READY state
		while(iterator.hasNext()){
			
			//get the address
			address = iterator.next();
			
			channel = connectionsMap.get(address);
			//get the plain tcp channel. Otherwise there is no point for the nagle algorithm
			if(channel instanceof PlainTCPChannel){
				
				//it is safe to cast to PlainTCPChannel
				plainTCPChannel = (PlainTCPChannel) channel;
				
				//enable/disable nagle
				try {
					plainTCPChannel.getSocket().setTcpNoDelay(!enableNagle);
				} catch (SocketException e) {

					Logging.getLogger().log(Level.WARNING, e.toString());
				}
			}
		    	   
		    
		}
		
	}
	
	/**
	 * Closes the channels and frees the resources.
	 */
	void closeAllConnections(){
		
		Channel channel;
		InetSocketAddress address;
		
		
		//set an iterator for the connection map.
		Iterator<InetSocketAddress> iterator = connectionsMap.keySet().iterator();
		
		//go over the map and check if all the connections are in READY state
		while(iterator.hasNext()){ 
			//get the address
			address = iterator.next();
			
			//get the channel
			channel = connectionsMap.get(address);
		       
			//close the channel
			channel.close();
		}
	}

}
