/**
 * Project: scapi.
 * Package: edu.biu.scapi.comm.
 * File: PlainChannel.java.
 * Creation date Feb 16, 2011
 * Created by LabTest
 *
 *
 * This file TODO
 */
package edu.biu.scapi.comm;

import java.io.IOException;

/**
 * @author LabTest
 *
 */
public abstract class PlainChannel implements Channel {

	public static enum State {
		
		NOT_INIT,
		CONNECTING,
		SECURING,
		READY

	}
	
	private State state;
	
	
	
	PlainChannel(){
		
		state = State.NOT_INIT;
	}

	/**
	 * returns the state of the channel. This class that implements the channel interface has a private attribute state. Other classes
	 * that implement channel (and the decorator abstract class) need to pass the request thru their channel private attribute.
	 */
	State getState() {
		
		return state;
	}

	/**
	 * Sets the state of the channel. This class that implements the channel interface has a private attribute state. Other classes
	 * that implement channel (and the decorator abstract class) need to pass the request thru their channel private attribute.
	 */
	void setState(PlainChannel.State state) {
		this.state = state; 
		
	}
	
	abstract boolean connect() throws IOException;
	
	abstract boolean isConnected();

}
