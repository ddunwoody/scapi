package edu.biu.scapi.interactiveMidProtocols.ot.otBatch.otExtension;

import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.OTBatchSOutput;


/**
 * Concrete implementation of batch OT sender's output.<p>
 * In this case there is an output for the sender which is the x0 and x1 that the OT has generated. 
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Meital Levy)
 *
 */
public class OTExtensionSOutput implements OTBatchSOutput {
	
	private byte[] x0Arr;	// An array that holds all x0 for all the senders serially. 
							// For optimization reasons, all the x0 inputs are held in one dimensional array one after the other 
							// rather than a two dimensional array. 
							// The size of each element can be calculated by x0Arr.length/numOfOts/
	
	private byte[] x1Arr;	// An array that holds all x1 for all the senders serially. 
	
	/**
	 * Constructor that sets all x0 and x1 for all senders.
	 * @param x0Arr holds all x0 for all the senders serially
	 * @param x1Arr holds all x1 for all the senders serially
	 */
	public OTExtensionSOutput(byte[] x0Arr, byte[] x1Arr){
		this.x0Arr = x0Arr;
		this.x1Arr = x1Arr;
	}
	
	/**
	 * @return the array that holds all x0 for all the senders serially. 
	 */
	public byte[] getX0Arr(){
		return x0Arr;
	}
	
	/**
	 * @return the array that holds all x1 for all the senders serially. 
	 */
	public byte[] getX1Arr(){
		return x1Arr;
	}
	
	

}
