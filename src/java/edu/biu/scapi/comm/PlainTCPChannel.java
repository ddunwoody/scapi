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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.logging.Level;

import edu.biu.scapi.generals.Logging;

/** 
 * This class represents a concrete channel in the Decorator Pattern used to create Channels. This channel ensures TCP type of communication.
 * In order to enforce the right usage of the Channel class we will restrict the ability to instantiate one, 
 * only to classes within the Communication Layer�s package. This means that the constructor of the channel will be unreachable from 
 * another package. However, the send, receive and close functions will be declared public, therefore allowing anyone holding a channel 
 * to be able to use them.
 *  
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 */
public class PlainTCPChannel extends PlainChannel{
	
	
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
	
	private Socket socket = new Socket();
	private ObjectOutputStream outStream;
	private ObjectInputStream inStream;
	private InetSocketAddress socketAddress;
	private Message intermediate;
	private Message msgObj;
	byte[] msgBytes;


	
	/**
	 * Creates a channel given the IP address and the port to connect to. 
	 * @param ipAddress other end's IP address
	 * @param port other end's port
	 */
	PlainTCPChannel(InetAddress ipAddress, int port) {
		
		socketAddress = new InetSocketAddress(ipAddress, port);
	}
	
	/**
	 * Creates a channel given an InetSocketAddress.
	 * @param socketAddress other end's InetSocketAddress
	 */
	PlainTCPChannel(InetSocketAddress socketAddress) {

		this.socketAddress = socketAddress;
	}

		
	
	/** 
	 * Sends the message to the other end-user of the channel with TCP protocol.
	 *  
	 * @param msg the object to send
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
		//System.out.println("Sending " + msg.getClass().getName());
		
		//outStream.writeObject(msg);
	}

	/** 
	 * Receives the message sent by the other end-user of the channel. 
	 * 
	 * @throws ClassNotFoundException  The Class of the serialized object cannot be found
	 * @throws IOException Any of the usual Input/Output related exceptions
	 */
	public Serializable receive() throws ClassNotFoundException, IOException {
		


		//We actually received a message of class Message. We translate it back to the original object that was sent by the user and return this object. 
		intermediate =   (Message) inStream.readObject();
		ByteArrayInputStream iInput = new ByteArrayInputStream(intermediate.getData());
		ObjectInputStream ois = new ObjectInputStream(iInput);
		
		return (Serializable) ois.readObject();
		
		
		//return (Serializable) inStream.readObject();
	}

	/**
	 * Closes the socket and all other used resources.
	 */
	public void close() {

		if(socket!=null){
			try {
				
				outStream.close();
				inStream.close();
				socket.close();
			} catch (IOException e) {

				Logging.getLogger().log(Level.WARNING, e.toString());
			}
			
		}
	}

	
	public boolean isClosed(){
		return socket.isInputShutdown() || socket.isOutputShutdown() || socket.isClosed() || !socket.isConnected();
	}

	
	/** 
	 * Connects the socket to the InetSocketAddress of this object. If the server we are trying to connect to 
	 * is not up yet then we sleep for a while and try again until the connection is established. This is done by the SecuringConnectionThread which keeps trying
	 * until it succeeds or a timeout has been reached.<p>		
	 * After the connection has succeeded the input and output streams are set for the send and receive functions.
	 * @return
	 * @throws IOException 
	 */
	boolean connect() throws IOException {
		
		//try to connect
		Logging.getLogger().log(Level.INFO, "Trying to connect to " + socketAddress.getAddress() + " on port " + socketAddress.getPort());
		
		
		//create and connect the socket. Cannot reconnect if the function connect fails since it closes the socket.
		socket = new Socket(socketAddress.getAddress(), socketAddress.getPort());
			
		if(socket.isConnected()){
			try {
				Logging.getLogger().log(Level.INFO, "Socket connected");
				outStream = new ObjectOutputStream(socket.getOutputStream());
				inStream = new ObjectInputStream(socket.getInputStream());
			} catch (IOException e) {
				
				Logging.getLogger().log(Level.FINEST, e.toString());
			}
		}
		
		return true;
		
	}
	
	/**
	 * Returns if the socket is connected
	 */
	boolean isConnected(){
		
		if(socket!=null)
			return socket.isConnected();
		else
			return false;
	}

	


	/**
	 * Sets the socket and the input and output streams. If the user uses this function it means that 
	 * the connect function will not be called and thus, the streams should be set here.
	 * @param socket the socket to set
	 * 		
	 */
	void setSocket(Socket socket) {
		this.socket = socket;
		
		try {
			//set t he input and output streams
			outStream = new ObjectOutputStream(socket.getOutputStream());
			inStream = new ObjectInputStream(socket.getInputStream());
		} catch (IOException e) {

			Logging.getLogger().log(Level.WARNING, e.toString());
		}
	}
	
	/**
	 * Return the underlying socket. Used only internally.
	 * @return the underlying socket
	 */
	Socket getSocket(){
		return socket;
	}

	
}
