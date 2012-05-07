/**
 * Project: scapi.
 * Package: edu.biu.scapi.comm.test.
 * File: AutomaticGenerations.java.
 * Creation date Mar 10, 2011
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
public class AutomaticGenerationsApp {

	/**
	 * main
	 * @param args
	 */
	public static void main(String[] args) {
		
		
		//AutomaticFilesBuilder propertiesBuilder = new AutomaticFilesBuilder(50, 8000, "132.70.6.63", "132.70.6.194", "Party");
		AutomaticFilesBuilder propertiesBuilder = new AutomaticFilesBuilder(10, 8000, "132.70.6.63", null, "Party");
		
		propertiesBuilder.generateAllPropertiesFiles();
		propertiesBuilder.generateAllBatchFiles();
	}

}
