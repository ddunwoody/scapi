/**
 * Project: scapi.
 * Package: edu.biu.scapi.comm.
 * File: KeyExchangeOutput.java.
 * Creation date Feb 15, 2011
 * Created by LabTest
 *
 *
 * This file TODO
 */
package edu.biu.scapi.comm;

import java.security.Key;

/**
 * @author LabTest
 *
 */
public class KeyExchangeOutput implements ProtocolOutput {

	private Key encKey;
	private Key macKey;
	
	/**
	 * 
	 */
	public KeyExchangeOutput() {
		
	}
	
	/**
	 * @param encKey the encKey to set
	 */
	void setEncKey(Key encKey) {
		this.encKey = encKey;
	}
	/**
	 * @return the encKey
	 */
	Key getEncKey() {
		return encKey;
	}
	/**
	 * @param macKey the macKey to set
	 */
	void setMacKey(Key macKey) {
		this.macKey = macKey;
	}
	/**
	 * @return the macKey
	 */
	Key getMacKey() {
		return macKey;
	}
	
	
}
