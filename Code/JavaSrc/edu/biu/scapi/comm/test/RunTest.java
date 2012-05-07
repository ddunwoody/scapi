/**
 * Project: scapi.
 * Package: edu.biu.scapi.comm.test.
 * File: RunTest.java.
 * Creation date Mar 13, 2011
 * Created by LabTest
 *
 *
 * This file TODO
 */
package edu.biu.scapi.comm.test;

/**
 * @author LabTest
 *
 */
public class RunTest {

	
	/**
	 * main
	 * @param args
	 */
	public static void main(String[] args) {

		int numOfParties = 0 ;
		//get the number of parties
		
		if(args.length>0)
			numOfParties = Integer.parseInt(args[0]);
		
		
		for(int i=0;i<numOfParties; i++){
			
			ExecutingThread executingThread = new ExecutingThread("Party" + i + ".bat", null);
		
			executingThread.start();
		}
	}

}
