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
 * A connection will be represented by a Channel class. We use the Decorator Design Pattern to implement different types of channels. 
 * In order to enforce the right usage of the Channel class we will restrict the ability to instantiate one, 
 * only to classes within the Communication Layer’s package. This means that the constructor of the channel will be unreachable from 
 * another package. However, the send, receive and close functions will be declared public, therefore allowing anyone holding a channel 
 * to be able to use them.
 * At the connecting state, each channel is held by the EstablishedConnections container as well as by a thread of type SecuringConnectionThread.
 */
package edu.biu.scapi.comm;

import java.io.IOException;
import java.io.Serializable;

/** 
 * @author LabTest
 */
public interface Channel{
	
	public void send(Serializable data) throws IOException;

	public Serializable receive() throws ClassNotFoundException, IOException;
	
	public void close();
	
	public boolean isClosed();
}
