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
 * Key Exchange Protocols are implemented using the Strategy design pattern so that different protocols can be chosen by the application. 
 * An instance of the chosen concrete class is passed to the CommunicationSetup. We will currently implement three options:
 *   •	Init key, in this protocol each party has already received as input the shared keys.
 *   •	Plain Diffie-Hellman Key Exchange.
 *   •	Universally Composable Diffie-Hellman.
 * Since Key Exchange Protocols are a type of Protocol, they also implement the Protocol Interface. 
 */
package edu.biu.scapi.comm;


/** 
 * For future implementation. 
 * This class represents a key exchange protocol to be run if encryption key and/or authentication keys need to be exchanged by the parties upon establishing the connection and before 
 * starting the actual communication.  
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University
 */
class KeyExchangeProtocol implements Protocol{

	
	/**
	 * 
	 */
	public KeyExchangeProtocol() {
		
	}
	
	/**
	 * 
	 */
	public ProtocolOutput getOutput() {

		return new KeyExchangeOutput();
	}

	/**
	 * 
	 */
	public void run() {
		// TODO Auto-generated method stub
		
	}

	/**
	 * 
	 */
	public void start(ProtocolInput protocolInput) {
		// TODO Auto-generated method stub
		
	}
}
