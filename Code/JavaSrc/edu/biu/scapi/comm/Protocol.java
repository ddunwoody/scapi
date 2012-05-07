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
