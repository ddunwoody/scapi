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
 
import java.util.Map;

import edu.biu.scapi.comm.Channel;

/** 
 * The TwoPartyCommunicationSetup interface manages the common functionality of all two party communications. 
 * There are several ways to communicate between two parties - using sockets, queues, etc. Each concrete way should implements this 
 * interface and the functions in it.<p>
 * This interface should be used in the specific case of communication between two parties, while CommunicationSetup should be used in
 * the extended case of multi-party communication.<p>
 * 
 * The Communications Layer package is a tool used by a client that is interested in setting up connections 
 * between itself and other party. As such, this layer does not initiate any independent tasks, but the opposite. Given two parties, 
 * it attempts to set connections to them according to parameters given by the calling application. If succeeds, it returns these 
 * connections so that the calling client can send and receive data over them.<p>
 * Note that multiple connections can be created although it is a two party communication; the user can ask to set any number of connections.
 * 
 * An application written for running a two party protocol can be the client of the Communications Layer. An example of a possible 
 * usage follows:<p>
 * <ul>
 * <li>Instantiate an object of type TwoPartyCommunicationSetup.</li>
 * <li>Call the prepareForCommunication method of that object with two parties to connect to and other setup parameters. 
 * (prepareForCommunication is the only public method of this class).</li>
 * <li>Get from prepareForCommunication a container holding all ready connections.</li>
 * <li>Start the two party protocol.</li> 
 * <li>Call the send and receive methods of the ready connections as needed by the protocol.</li>
 * </ul>
 * The application may be interested in putting each connection in a different thread but it is up to the application to do so and not 
 * the responsibility of the Communications Layer. This provides more flexibility of use.
 * 
 * CommunicationSetup implements the org.apache.commons.exec.TimeoutObserver interface. 
 * This interface supplies a mechanism for notifying classes that a timeout has arrived. 
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public interface TwoPartyCommunicationSetup {

	/**
	 * An application that wants to use the communication layer will call this function in order to prepare for 
	 * communication after providing the required parameters. <p>
	 * The constructor of the concrete classes should receive the data of the two parties participate in the communication.
	 * After that, this function initiates the creation of the final actual connections between the parties. <p>
	 * Each connection has a unique name, that we call ID. This name used to distinguish between the created connections
	 * in order to make it easier and more convenient to understand what is the usage of each connection.<p>
	 * If this function succeeds, the application may use the send and receive functions of the created channels to 
	 * pass messages.<p> 
	 * In this function, Nagle’s algorithm is disabled; for cryptographic protocols this is typically much better.
	 * 
	 * @param connectionsIds Each required connection's name.
	 * @param timeOut the maximum amount of time we allow for the connection stage.
	 * @return a map contains the connected channels. The key to the map is the id of the connection.
	 */
	public Map<String, Channel> prepareForCommunication(String[] connectionsIds, long timeOut);
	
	/**
	 * An application that wants to use the communication layer will call this function in order to prepare for 
	 * communication after providing the required parameters. <p>
	 * The constructor of the concrete classes should receive the data of the two parties participate in the communication.
	 * After that, this function initiates the creation of the final actual connections between the parties. <p>
	 * Each connection has a unique name, that we call ID. This name used to distinguish between the created connections
	 * in order to make it easier and more convenient to understand what is the usage of each connection. 
	 * In this function, the names of the connections are chosen by default, meaning the connections are numbered 
	 * according to their index. i.e the first connection's name is "1", the second is "2" and so on.<p>
	 * If this function succeeds, the application may use the send and receive functions of the created channels to 
	 * pass messages.<p> 
	 * Note that using this function you can choose to use or not to use the Nagle algorithm.
	 * 
	 * @param connectionsNum The number of requested connections.
	 * @param timeOut the maximum amount of time we allow for the connection stage.
	 * @return a map contains the connected channels. The key to the map is the id of the connection.
	 */
	public Map<String, Channel> prepareForCommunication(int connectionsNum, long timeOut);
	
	/**
	 * Enables to use Nagle algrithm in the communication. <p>
	 * By default Nagle algorithm is disabled since it is much better for cryptographic algorithms.
	 * 
	 */
	public void enableNagle();
	
	/**
	 * There are several implementations that should close the communication object. 
	 */
	public void close();
}
