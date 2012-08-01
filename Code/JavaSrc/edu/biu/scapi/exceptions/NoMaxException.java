package edu.biu.scapi.exceptions;

public class NoMaxException extends RuntimeException{

	private static final long serialVersionUID = 6771806427107812842L;

	/**
     * base constructor.
     */
    public NoMaxException()
    {
    }

    /**
     * 
     * @param message the message to be carried with the exception.
     */
    public NoMaxException(String  message)
    {
        super(message);
    }
}
