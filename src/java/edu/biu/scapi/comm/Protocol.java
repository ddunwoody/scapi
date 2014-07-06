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
 * For future implementation.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University
 *
 */
public interface Protocol {

	public void start(ProtocolInput protocolInput);
	public void run();
	public ProtocolOutput getOutput();
	
}
