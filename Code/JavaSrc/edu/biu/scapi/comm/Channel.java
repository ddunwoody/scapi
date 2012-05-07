/**
 * A connection will be represented by a Channel class. We use the Decorator Design Pattern to implement different types of channels. 
 * In order to enforce the right usage of the Channel class we will restrict the ability to instantiate one, 
 * only to classes within the Communication Layer’s package. This means that the constructor of the channel will be unreachable from 
 * another package. However, the send, receive and close functions will be declared public, therefore allowing anyone holding a channel 
 * to be able to use them.
 * At the connecting state, each channel is held by the EstablishedConnections container as well as by a thread of type SecuringConnectionThread.
 */
package edu.biu.scapi.comm;

import java.io.IOException;

/** 
 * @author LabTest
 */
public interface Channel{
	
	public void send(Message msg) throws IOException;

	public Message receive() throws ClassNotFoundException, IOException;
	
	public void close();
}