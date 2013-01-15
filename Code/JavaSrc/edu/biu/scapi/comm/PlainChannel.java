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

/*
 * Abstract class that holds data and functionality common to different types of concrete channels.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Ley)
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
