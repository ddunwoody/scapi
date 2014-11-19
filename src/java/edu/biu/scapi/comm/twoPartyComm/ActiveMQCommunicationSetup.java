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

import javax.jms.Connection;
import javax.jms.Destination;
import javax.jms.JMSException;

import org.apache.activemq.ActiveMQConnection;
import org.apache.activemq.ActiveMQConnectionFactory;
import org.apache.activemq.command.ActiveMQDestination;

import edu.biu.scapi.exceptions.DuplicatePartyException;

/**
 * This class is an example of {@link QueueCommunicationSetup} that uses the ActiveMQ implementation of the JMS.
 * The constructor of this class create the ActiveMQ connection factory and the ActiveMQDestroyer and pass it to the 
 * constructor of the QueueCommunicationSetup to work with.
 * 
 *  * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class ActiveMQCommunicationSetup extends QueueCommunicationSetup{
	
	public ActiveMQCommunicationSetup(String url, PartyData me, PartyData party) throws DuplicatePartyException {
		
		// Create an ActiveMQConnectionFactory with the given URL, and enable/disable nagle's algorithm (by defining 
		//tcpNoDelay) using the given enableNagle.		
		//Call the constructor of QueueCommunicationSetup with the creates factory and the ActiveMQDestroyer objects 
		//in order to communicate using the ActiveMQ implementation.
		super(new ActiveMQConnectionFactory("failover:tcp://"+url+"?socket.tcpNoDelay="+!enableNagle), new ActiveMQDestroyer(), me, party);
		
	}
	
	/**
	 * A class that distruct the ActiveMQ destinations using the ActiveMQ connection.
	 * 
	 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
	 */
	public static class ActiveMQDestroyer implements DestroyDestinationUtil{

		@Override
		public void destroyDestination(Connection connection, Destination destinationName) throws JMSException {
			//Cast the connection and destination objects to ActiveMQ objects and call the destroyDestination function
			//of ActiveMQ.
			((ActiveMQConnection)connection).destroyDestination((ActiveMQDestination)destinationName);
			
		}
		
	}

}
