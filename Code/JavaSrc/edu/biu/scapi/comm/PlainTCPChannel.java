/**
 * 
 */
package edu.biu.scapi.comm;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.logging.Level;

import edu.biu.scapi.generals.Logging;

/** 
 * @author LabTest
 */
public class PlainTCPChannel extends PlainChannel{
	private Socket socket = new Socket();
	private ObjectOutputStream outStream;
	private ObjectInputStream inStream;
	private InetSocketAddress socketAddress;

	
	/** 
	 * @param ipAddress
	 * @param port
	 */
	PlainTCPChannel(InetAddress ipAddress, int port) {
		
		socketAddress = new InetSocketAddress(ipAddress, port);
	}
	
	/**
	 * 
	 */
	public PlainTCPChannel(InetSocketAddress socketAddress) {

		this.socketAddress = socketAddress;
	}

	/** 
	 * @param existingChannel
	 */
	PlainTCPChannel(Channel existingChannel) {
		// begin-user-code
		// TODO Auto-generated constructor stub
		// end-user-code
	}

	/** 
	 * @param ipAddress
	 * @param port
	 * @param typeOfConnection
	 */
	PlainTCPChannel(InetAddress ipAddress, int port, Object typeOfConnection) {
		
	}

	
	
	
	/** 
	 * @param msg
	 * @throws IOException 
	 */
	public void send(Message msg) throws IOException {
		
		
		
		outStream.writeObject(msg);
		
		System.out.println("Sending " + msg.getData()[0] + msg.getData()[1]);
	}

	/** 
	 * @throws ClassNotFoundException 
	 * @throws IOException 
	 */
	public Message receive() throws ClassNotFoundException, IOException {
		
		
		Message msg = (Message)inStream.readObject();
		int accum=0;
		for(int i=0;i<(msg.getData()).length; i++){
			
			accum+=msg.getData()[i];
		}
		
		System.out.println("receiving... " +  accum);
		
		return msg;
	}

	/**
	 * 
	 * Closes the socket and the out and in streams.
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

	
	/** 
	 * Connects the socket to the InetSocketAddress of this object. If the server we are trying to connect to 
	 * 			 is not up yet than we sleep for a while and try again until the connection is established.
	 * 			 After the connection has succeeded the input and output streams are set for the send and receive functions.
	 * @return
	 * @throws IOException 
	 */
	boolean connect() throws IOException {
		
		//try to connect
		Logging.getLogger().log(Level.INFO, "Trying to connect to " + socketAddress.getAddress() + " on port " + socketAddress.getPort());
		
		
		//create and connect the socket. Cannot reconnect if the function connect fails since it closes the socket.
		socket = new Socket(socketAddress.getAddress(), socketAddress.getPort());
		//socket.connect(socketAddress,1000);
			
		
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
	 * returns if the socket is connected
	 */
	boolean isConnected(){
		
		if(socket!=null)
			return socket.isConnected();
		else
			return false;
	}

	


	/**
	 * Sets the socket and the input and output streams. If the user uses this function it means that 
	 * 			   the connect function will not be called and thus, the streams should be set here.
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
	
	Socket getSocket(){
		return socket;
	}


	
}