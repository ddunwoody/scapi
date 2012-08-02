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
 * File: Protocol.java.
 * Creation date Feb 15, 2011
 * Created by LabTest
 *
 * Any algorithm that needs to be run by an application as a protocol has to implement the Protocol Interface. It has three methods:
 * •	start(ProtocolInput); initialize input
 * •	run(); run the protocol
 * •	getOutput(); returns an object of type Output.
 * Any necessary data has to be provided to the concrete protocol in the start() function as an object of type ProtocolInput. 
 * This data will be used inside the methods. Each protocol may have a specific type of ProtocolInput. 
 * Having the data passed to the protocol object in the start() function allows for repeated runs of the protocol such that in between 
 * runs the state of the previous run can be saved and new data can be provided in phases.  
 * The output will be returned in an object of a class that implements the Output interface. 
 * Anything that needs to be returned as the output of a protocol has to implement the Output interface
 */
package edu.biu.scapi.comm;

/**
 * @author LabTest
 *
 */
public interface Protocol {

	public void start(ProtocolInput protocolInput);
	public void run();
	public ProtocolOutput getOutput();
	
}
