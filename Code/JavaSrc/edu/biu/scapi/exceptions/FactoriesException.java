package edu.biu.scapi.exceptions;

import java.io.PrintStream;
import java.io.PrintWriter;

public class FactoriesException extends Exception {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	Exception exc;
	
	public FactoriesException(Exception e){
		exc = new Exception();
		exc = e;
	}
	
	/*public Throwable fillInStackTrace(){
		return exc.fillInStackTrace();
	}*/
     
	public Throwable getCause(){
		return exc.getCause();
	}
     
	public String getLocalizedMessage(){
		return exc.getLocalizedMessage();
	}
     
	public String getMessage(){
		return exc.getMessage();
	}
     
	public StackTraceElement[] getStackTrace(){
		return exc.getStackTrace();
	}
     
	public Throwable initCause(Throwable cause){
		return exc.initCause(cause);
	}
	
	public void printStackTrace(){
		exc.printStackTrace();
	}
     
	public void printStackTrace(PrintStream s){
		exc.printStackTrace(s);
	}

	public void printStackTrace(PrintWriter s){
		exc.printStackTrace(s);
	}
     
	public void setStackTrace(StackTraceElement[] stackTrace){
		exc.setStackTrace(stackTrace);
	}
     
	public String toString(){
		return exc.toString();
	}
}