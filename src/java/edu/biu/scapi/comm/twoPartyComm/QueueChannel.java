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

import java.io.Serializable;

import javax.jms.Connection;
import javax.jms.DeliveryMode;
import javax.jms.Destination;
import javax.jms.JMSException;
import javax.jms.MessageConsumer;
import javax.jms.MessageProducer;
import javax.jms.ObjectMessage;
import javax.jms.Session;
import javax.jms.Message;

import edu.biu.scapi.comm.Channel;

/**
 * This class represents a concrete channel in the Decorator Pattern used to create Channels. This channel uses the 
 * JMS mechanism and can work on any concrete implementation, by getting a concrete Connection object in the constructor.<P>
 *  
 * The JMS mechanism provides a way of messaging. We use a peer-to-peer facility: A messaging client can send 
 * messages to, and receive messages from, any other client. 
 * Each client connects to a messaging agent that provides facilities for creating, sending, receiving, and 
 * reading messages.
 * JMS enables distributed communication that is loosely coupled. A component sends a message to a destination, 
 * and the recipient can retrieve the message from the destination. 
 * However, the sender and the receiver do not have to be available at the same time in order to communicate. 
 * In fact, the sender does not need to know anything about the receiver; nor does the receiver need to know anything 
 * about the sender. The sender and the receiver need to know only which message format and which destination to use.
 * In this respect, messaging differs from tightly coupled technologies, such as Remote Method Invocation (RMI), 
 * which require an application to know a remote application’s methods.<p>
 * 
 * In order to enforce the right usage of the Channel class we will restrict the ability to instantiate one, 
 * only to classes within the Communication Layer’s package. This means that the constructor of the channel will be 
 * unreachable from another package. However, the send, receive and close functions will be declared public, therefore 
 * allowing anyone holding a channel to be able to use them.<p>
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
class QueueChannel implements Channel{
	//A session is a single-threaded context for producing and consuming messages.
	//We use a different sessions for send and receive messages.
	private Session session;
	private MessageProducer producer;	// Used to send messages.
	private MessageConsumer consumer;	//Used to receive messages.
	private boolean isClosed;
	//As a convention, each queue should be deleted at the end of the communication by the consumer of this queue.
	//(Thus, the producer queue will be deleted by the other side of the communication).
	private Destination consumerQueue;	//We save it in order to remove it at the end of the communication.
	private Connection connection;		//We save because we need it to remove the consumer queue at the end of the communication.
	private DestroyDestinationUtil destroyer;
	
	/**
	 * A constructor that gets the two parties, the Connection object to use and the number of connections.
	 * It create the producer and consumer sessions and build a queue to send messages on and a queue to receive messages from. 
	 * The names of the queues are unique and are in the following format:
	 * "channel {connectionNumber} From {id of the queue producer} To {id of the queue consumer}".
	 * @param first The party which declares the running program.
	 * @param second The party which declares the other program.
	 * @param connection The JMS connection object to build the producer and consumer on.
	 * @param connectionsId the id of this connection.
	 * @param destroyer The class that delete the created destinations. Should match to the given connection object.
	 */
	QueueChannel(QueuePartyData first, QueuePartyData second, Connection connection, String connectionsId, DestroyDestinationUtil destroyer) {
		try {
			this.connection = connection;
			
			//Create the channel session.
			session = connection.createSession(false, Session.AUTO_ACKNOWLEDGE);
			//Create the producer queue.
			//String producerQueueName = "channel " +connectionsId+" From"+first.getId() + "To:"+ second.getId();
			String producerQueueName = connectionsId+" "+first.getId() + " "+ second.getId();
			Destination producerQueue = session.createQueue(producerQueueName);
			//Create the producer object.
			producer = session.createProducer(producerQueue);
			producer.setDeliveryMode(DeliveryMode.NON_PERSISTENT);
			
			//Create the consumer queue.
			//String consumerQueueName = "channel " +connectionsId+" From"+second.getId() + "To:"+ first.getId();
			String consumerQueueName = connectionsId+" "+second.getId() + " "+ first.getId();
			//consumerQueue = consumerSession.createQueue(consumerQueueName);
			consumerQueue = session.createQueue(consumerQueueName);
			//Create the consumer object.
			//consumer = consumerSession.createConsumer(consumerQueue);
			consumer = session.createConsumer(consumerQueue);
			
			isClosed = false;
			this.destroyer = destroyer;
		} catch (JMSException e) {
			throw new edu.biu.scapi.exceptions.JMSException(e.getMessage());
		}
	}

	@Override
	public void send(Serializable data) {
		try{
			//Send the message using the producer queue.
			ObjectMessage message = session.createObjectMessage(data);
			producer.send(message);	
		
			//We cast the exception to SCAPI exception which is a runtime exception.
			//That way we do not need to declare the function to throw this exception.
		} catch(JMSException e){
			throw new edu.biu.scapi.exceptions.JMSException(e.getMessage());
		}
		
		
	}

	@Override
	public Serializable receive() {
		try {
			//Receive the message using the consumer.
			Message message = consumer.receive();
			//Check that the received message is instance of ObjectMessage.
			if (!(message instanceof ObjectMessage)){
				throw new IllegalArgumentException("message should be an instance of ObjectMessage");
			}
			
			//We cast the exception to SCAPI exception which is a runtime exception.
			//That way we do not need to declare the function to throw this exception.
			return ((ObjectMessage)message).getObject();
		} catch (JMSException e) {
			throw new edu.biu.scapi.exceptions.JMSException(e.getMessage());
		}
	}

	@Override
	public void close(){
		try {
			//Close the producer and consumer.
			producer.close();
			consumer.close();
			//Close the session.
			session.close();
			isClosed = true;
			//As a convention, each queue should be deleted at the end of the communication by the consumer of this queue.
			//(Thus, the producer queue will be deleted by the other side of the communication).
			destroyer.destroyDestination(connection, consumerQueue);
		} catch (JMSException e) {
			throw new edu.biu.scapi.exceptions.JMSException(e.getMessage());
		}
		
	}

	@Override
	public boolean isClosed() {
		
		return isClosed;
	}

}
