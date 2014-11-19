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

import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import edu.biu.scapi.comm.Channel;

/**
 * The SocketCommunicationSetup class holds a container of type EstablishedSocketConnections that keeps track of the 
 * connections (channels) as they are being established. This container has a number of channels that can be in different
 * states. <P>
 * EstablishedSocketConnections has regular operations of containers such as add and remove. 
 * It also has logical operations such as areAllConnected.<p>
 * At the end of the “prepare for communication” method, the calling application receives a map of connections in the 
 * EstablishedConnections object held by the CommunicationSetup. At this stage, all the channels in EstablishedConnections 
 * object need to be in READY state. 
 * It is possible that this object will be null if the “prepare for communication” did not succeed. 
 * The key to the map is the id of the connection.    
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
class EstablishedSocketConnections {
	private Map<String, Channel> connectionsMap;

	
	/**
	 * Constructor that create the connections map.
	 */
	EstablishedSocketConnections() {
		//Initiate the map.
		connectionsMap = new HashMap<String,Channel>();
	}

	/**
	 * @return the connections map.
	 */
	Map<String, Channel> getConnections() {
		return connectionsMap;
	}
	
	/** 
	 * Adds a channel with the id to the map.
	 * @param connectionsIds the unique id of the connection which is the key to the map.
	 * @param connection the channel to insert to the map.
	 */
	void addConnection(String connectionsIds, Channel connection) {

		// Add the channel to the map.
		connectionsMap.put(connectionsIds, connection);
	}

	/** 
	 * Removes a channel from the map.
	 * @param id the unique id of the connection which is the key to the map.
	 */
	Channel removeConnection(String id) {
		
		//Remove the connection.
		return connectionsMap.remove(id);
	}

	/** 
	 * Gets a channel from the map.
	 * @param id the unique id of the connection which is the key to the map.
	 */
	Channel getConnection(String id) {
		
		//Get the connection according to the given id.
		return connectionsMap.get(id);
	}

	
	/** 
	 * @return the number of channels in the map.
	 */
	int getConnectionsCount() {
		
		return connectionsMap.size();
	}

	/** 
	 * @return true if all the channels are in READY state, false otherwise.
	 */
	boolean areAllConnected() {

		//Set an iterator for the connection map.
		Collection<Channel> c = connectionsMap.values();
		Iterator<Channel> itr = c.iterator();
		
		PlainTCPSocketChannel plainChannel;
		//Go over the map and check if all the connections are in READY state.
		while(itr.hasNext()){
			plainChannel = (PlainTCPSocketChannel)itr.next();
		       if(plainChannel.getState()!=PlainTCPSocketChannel.State.READY){
		    	   return false;
		       }
		}
		
		return true;
	}
	
	/**
	 * 
	 * Removes all the connections which are not in READY state.
	 * 
	 * Note	: The connection can be removed only by the iterator and not directly through the map. 
	 * 		  Otherwise an exception will be thrown.
	 */
	void removeNotReadyConnections(){
		
		PlainTCPSocketChannel plainChannel;
		String id;
			
		//Set an iterator for the connection map.
		Iterator<String> iterator = connectionsMap.keySet().iterator();
		
		//Go over the map and remove every channel that is not in READY state.
		while(iterator.hasNext()){ 
			id = iterator.next();
			plainChannel = (PlainTCPSocketChannel) connectionsMap.get(id);
			if(plainChannel.getState() != PlainTCPSocketChannel.State.READY){

	    	   connectionsMap.remove(id);	   
	       }
		}	
	}
	
	/**
	 * 
	 * @param enableNagle true for enabling Nagle, otherwise false.
	 */
	void enableNagle(boolean enableNagle){
		
		PlainTCPSocketChannel plainTCPChannel;
		Channel channel;
		String id;
		
		//Set an iterator for the connection map.
		Iterator<String> iterator = connectionsMap.keySet().iterator();
		
		//Go over the map and enable/disable each channel with the Nagle algorithm.
		while(iterator.hasNext()){
			
			//Get the channel.
			id = iterator.next();
			channel = connectionsMap.get(id);
			
			//Check if the channel is a plain tcp channel. Otherwise there is no point for the Nagle algorithm.
			if(channel instanceof PlainTCPSocketChannel){
				plainTCPChannel = (PlainTCPSocketChannel) channel;
				
				//Enable/disable nagle.
				plainTCPChannel.enableNage(enableNagle);			
			}	    	   	    
		}	
	}
	
	/**
	 * Closes the channels and frees the resources.
	 */
	void closeAllConnections(){
		
		Channel channel;
		String id;
		
		//Set an iterator for the connection map.
		Iterator<String> iterator = connectionsMap.keySet().iterator();
		
		//Go over the map and close all connection.
		while(iterator.hasNext()){ 
			//Get the channel.
			id = iterator.next();
			channel = connectionsMap.get(id);
		       
			//Close the channel.
			channel.close();
		}
	}

}
