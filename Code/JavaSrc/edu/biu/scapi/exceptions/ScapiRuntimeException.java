package edu.biu.scapi.exceptions;

public class ScapiRuntimeException extends RuntimeException {
	  /**
	 * 
	 */
	private static final long serialVersionUID = -8883358405605726578L;

	/**
     * base constructor.
     */
    public ScapiRuntimeException()
    {
    }

    /**
     * ScapiRuntimeException is thrown when cryptographic operations have been attempted without success<p>
     * and the general interface does not provide a suitable exception.  
     *
     * @param message the message to be carried with the exception.
     */
    public ScapiRuntimeException(String  message)
    {
        super(message);
    }
}
