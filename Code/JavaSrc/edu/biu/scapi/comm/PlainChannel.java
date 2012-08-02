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
