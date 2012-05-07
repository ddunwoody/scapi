/**
 * This exception class inherits from RuntimeException. There is no way to continue if this exception is thrown. The code must be corrected.
 * Having to declare such exceptions would not aid significantly in establishing the correctness of the application.
 */
package edu.biu.scapi.exceptions;

/**
 * @author LabTest
 *
 */
public class InvalidChannel extends RuntimeException{


	private static final long serialVersionUID = -9060767436209580708L;


	public InvalidChannel() {
		// TODO Auto-generated constructor stub
	}
	
	public InvalidChannel(String message){
		super(message);
	}
}
