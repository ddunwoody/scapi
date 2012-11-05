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
 * The CommunicationSetup class holds a container of type EstablishedConnections that keeps track of the connections (channels) 
 * as they are being established. This container has a number of channels that can be in different states.
 * EstablishedConnections has regular operations of containers such as add and remove. It also has logical operations such as areAllConnected.
 * At the end of the “prepare for communication” method, the calling application receives a map of connections in the EstablishedConnections 
 * object held by the CommunicationSetup. At this stage, all the channels in EstablishedConnections object need to be in READY state. 
 * It is possible that this object will be null if the “prepare for communication” did not succeed. 
 * The key to the map is an object of type InetSocketAddress that holds the IP and the port. Since the IP and port are unique, 
 * they define a unique InetSocketAddress that can serve as a key to the map.   
 */
package edu.biu.scapi.comm;

import java.net.InetSocketAddress;
import java.net.SocketException;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.logging.Level;

import edu.biu.scapi.exceptions.InvalidChannel;
import edu.biu.scapi.generals.Logging;


/** 
 * @author LabTest
  */
public class EstablishedConnections {
	private Map<InetSocketAddress,Channel> connectionsMap;
	//private Set<Channel> channels;

	
	/**
	 * 
	 */
	public EstablishedConnections() {
		//initiate the map
		connectionsMap = new HashMap<InetSocketAddress,Channel>();
	}
	


	/**
	 * @return the connections
	 */
	public Map<InetSocketAddress,Channel> getConnections() {
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
	void updateConnectionState(InetSocketAddress address, PlainChannel.State state) throws InvalidChannel {

		//get the channel from the map
		Channel channel = connectionsMap.get(address);
		
		if(channel instanceof PlainChannel){
			PlainChannel plainChannel = (PlainChannel)channel;
		
			plainChannel.setState(state);
		}
		else
			throw new InvalidChannel("The related channel must be a plain channel");
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
