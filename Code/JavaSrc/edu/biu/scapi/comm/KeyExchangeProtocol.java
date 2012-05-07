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
* @author LabTest
 */
public class KeyExchangeProtocol implements Protocol{

	
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