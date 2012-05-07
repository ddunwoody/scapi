package edu.biu.scapi.exceptions;

public class UnInitializedException extends Exception{

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private String msg = null;
	
	public UnInitializedException(String message){
		msg = message;
	}
	
	public UnInitializedException(){
		msg = "cannot perform any function before initialization";
	}
	
	public String getMessage(){
		return msg;
	}
}
