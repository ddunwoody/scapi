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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketException;
import java.util.logging.Level;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.comm.PlainTCPChannel;
import edu.biu.scapi.generals.Logging;

/**
 * This class represents a concrete channel in the Decorator Pattern used to create Channels. This channel ensures TCP 
 * type of communication.
 * In order to enforce the right usage of the Channel class we will restrict the ability to instantiate one, 
 * only to classes within the Communication Layer’s package. This means that the constructor of the channel will be 
 * unreachable from another package. However, the send, receive and close functions will be declared public, therefore 
 * allowing anyone holding a channel to be able to use them.
 *  
 * The difference between this implementation to the {@link PlainTCPChannel} is that here there are two sockets: 
 * one used to receive messages and one used to send messages. The other {@link PlainTCPChannel} has one socket used 
 * both to send and receive. 
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
class PlainTCPSocketChannel implements Channel{
	
	/**
	 * A channel has a state. It can be either NOT_INIT,CONNECTING or READY.
	 * 
	 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
	 */
	public static enum State {
		
		NOT_INIT,
		CONNECTING,
		READY
	}
	
	/**
	 * 
	 * A nested class to use in the send and receive functions. 
	 */
	public static class Message implements Serializable{
		
		private static final long serialVersionUID = 4996749071831550038L;
		private byte[] data = null;
		
		public Message(byte[] data) {
			this.data = data;
		}
		public void setData(byte[] data) {
			this.data = data;
		}
		public byte[] getData() {
			return data;
		}
			
	}
	
	protected State state;						// The state of the channel.
	protected Socket sendSocket;					//A socket used to send messages.
	private Socket receiveSocket;				//A socket used to receive messages.
	protected ObjectOutputStream outStream;		//Used to send a message
	private ObjectInputStream inStream;			//Used to receive a message.
	protected InetSocketAddress socketAddress;	//The address of the other party.
	private Message intermediate;
	private Message msgObj;
	byte[] msgBytes;

	/**
	 * A constructor that set the state of this channel to not ready.
	 */
	PlainTCPSocketChannel(){
		
		state = State.NOT_INIT;
	}
	
	/**
	 * A constructor that create the socket address according to the given ip and port and set the state of this channel to not ready.
	 * @param ipAddress other party's IP address.
	 * @param port other party's port.
	 */
	PlainTCPSocketChannel(InetAddress ipAddress, int port) {
		
		this();
		socketAddress = new InetSocketAddress(ipAddress, port);
	}
	
	/**
	 * A constructor that set the given socket address and set the state of this channel to not ready.
	 * @param socketAddress other end's InetSocketAddress
	 */
	PlainTCPSocketChannel(InetSocketAddress socketAddress) {
		
		this();
		this.socketAddress = socketAddress;
	}

	/**
	 * Returns the state of the channel. 
	 */
	State getState() {
		
		return state;
	}

	/**
	 * Sets the state of the channel. 
	 */
	void setState(State state) {
		this.state = state; 
		
	}

	/** 
	 * Sends the message to the other user of the channel with TCP protocol.
	 *  
	 * @param msg the object to send.
	 * @throws IOException Any of the usual Input/Output related exceptions.  
	 */
	public void send(Serializable msg) throws IOException {
		//For some reason it turns out that writing complex objects first to a byte array message is faster than using the stream
		//of the socket to write the object. Thus we create here a Message object and translate it back to the actual object in the receive method
		//The use of a local stream that does the writeObject is faster than the writeObject of outStream member variable of this class
				
		ByteArrayOutputStream bOut = new ByteArrayOutputStream();  
	    ObjectOutputStream oOut  = new ObjectOutputStream(bOut);
		oOut.writeObject(msg);  
		oOut.close();
		
		msgBytes = bOut.toByteArray();
		msgObj = new Message(null);
		msgObj.setData(msgBytes);
		outStream.writeObject(msgObj);
		outStream.reset();
		
	}

	/** 
	 * Receives the message sent by the other user of the channel. 
	 * 
	 * @throws ClassNotFoundException  The Class of the serialized object cannot be found.
	 * @throws IOException Any of the usual Input/Output related exceptions.
	 */
	public Serializable receive() throws ClassNotFoundException, IOException {
		
		//We actually received a message of class Message. We translate it back to the original object that was sent by the user and return this object. 
		intermediate =   (Message) inStream.readObject();
		ByteArrayInputStream iInput = new ByteArrayInputStream(intermediate.getData());
		ObjectInputStream ois = new ObjectInputStream(iInput);
		
		return (Serializable) ois.readObject();
		
	}

	/**
	 * Closes the sockets and all other used resources.
	 */
	public void close() {

		try {
			if(sendSocket != null){
				outStream.close();
				sendSocket.close();
				
			}
			if(receiveSocket != null){
				
				inStream.close();
				receiveSocket.close();
			}
		} catch (IOException e) {
			
			Logging.getLogger().log(Level.WARNING, e.toString());
		}
	}

	/**
	 * Checks if the channel os closed or not.
	 * @return true if the channel is closed; False, otherwise.
	 */
	public boolean isClosed(){
		return receiveSocket.isInputShutdown() || sendSocket.isOutputShutdown() || 
				sendSocket.isClosed() || receiveSocket.isClosed() || 
				!sendSocket.isConnected() || !receiveSocket.isConnected();
	}

	
	/** 
	 * Connects the socket to the InetSocketAddress of this object. If the server we are trying to connect to 
	 * is not up yet then we sleep for a while and try again until the connection is established. 
	 * This is done by the {@link SocketCommunicationSetup} which keeps trying until it succeeds or a timeout has 
	 * been reached.<p>		
	 * After the connection has succeeded the output stream is set for the send function.
	 * @throws IOException 
	 */
	void connect()  {
		
		//try to connect
		Logging.getLogger().log(Level.INFO, "Trying to connect to " + socketAddress.getAddress() + " on port " + socketAddress.getPort());
		try {
			//create and connect the socket. Cannot reconnect if the function connect fails since it closes the socket.
			sendSocket = new Socket(socketAddress.getAddress(), socketAddress.getPort());
			
			if(sendSocket.isConnected()){
				
				Logging.getLogger().log(Level.INFO, "Socket connected");
				outStream = new ObjectOutputStream(sendSocket.getOutputStream());
				
				//After the send socket is connected, need to check if the receive socket is also connected.
				//If so, set the channel state to READY.
				setReady();
			}	
		} catch (IOException e) {
			
			Logging.getLogger().log(Level.FINEST, e.toString());
		}
	}
	
	/**
	 * Returns if the send socket is connected.
	 */
	boolean isSendConnected(){
		
		if(sendSocket!=null){
			
			return sendSocket.isConnected();
		
		} else{
			return false;
		}
	}

	/**
	 * Sets the receive socket and the input stream. 
	 * @param socket the receive socket to set.
	 * 		
	 */
	void setReceiveSocket(Socket socket) {
		this.receiveSocket = socket;
		
		try {
			//set the input and output streams
			inStream = new ObjectInputStream(socket.getInputStream());
			//After the receive socket is connected, need to check if the send socket is also connected.
			//If so, set the channel state to READY.
			setReady();
		} catch (IOException e) {

			Logging.getLogger().log(Level.WARNING, e.toString());
		}
	}
	
	/**
	 * This function sets the channel state to READY in case both send and receive sockets are connected.
	 */
	protected void setReady() {
		if(sendSocket != null && receiveSocket != null){
			
			if (sendSocket.isConnected() && receiveSocket.isConnected()){
				//set the channel state to READY
				state = State.READY;
				Logging.getLogger().log(Level.INFO, "state: ready " + toString());				
			}
		}
	}

	/**
	 * Enable/disable the Nagle algorithm according to the given boolean.
	 * @param enableNagle.
	 */
	void enableNage(boolean enableNagle) {
		try {
			sendSocket.setTcpNoDelay(!enableNagle);
			receiveSocket.setTcpNoDelay(!enableNagle);
		} catch (SocketException e) {
			Logging.getLogger().log(Level.WARNING, e.toString());
		}
	}

	

}
