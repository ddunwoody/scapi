/**
 * Project: scapi.
 * Package: edu.biu.scapi.comm.test.
 * File: AutomaticPropertiesFilesBuilder.java.
 * Creation date Mar 8, 2011
 * Created by LabTest
 *
 *
 * This file TODO
 */
package edu.biu.scapi.comm.test;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Properties;

/**
 * @author LabTest
 *
 */
public class AutomaticFilesBuilder {
	
	int numOfParties;
	int startPort;
	String commomIpAddress;
	String secondIpAddress;
	String startFilename;
	Properties properties;
	
	/**
	 * 
	 */
	public AutomaticFilesBuilder(int numOfParties, int startPort, String commomIpAddress, String secondIpAddress, String startFilename) {
		
		this .numOfParties = numOfParties;
		this.startPort = startPort;
		this.commomIpAddress = commomIpAddress;
		this.secondIpAddress = secondIpAddress;
		this.startFilename = startFilename;
		properties = new Properties();
		
		
	}
	
	void generateAllBatchFiles(){
		
		for(int i=0;i<numOfParties; i++){
				
			BufferedWriter output = null;
		    String text = "java -jar comTest.jar " + startFilename + i + ".properties";
		    File file = new File(startFilename + i + ".bat");
		    try {
				output = new BufferedWriter(new FileWriter(file));
				output.write(text);
				output.newLine();
				output.write("pause");
			    output.close();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		    
		}
	}
	
	void generateAllPropertiesFiles(){
		
		//generate the first file
		properties.setProperty("NumOfParties", "" + numOfParties);
		
		//set the properties for the first file
		for(int i=0;i<numOfParties; i++){
			
			properties.setProperty("Port" + i, "" + (startPort + i));
			properties.setProperty("IP" + i, commomIpAddress);
		}
		
		if(secondIpAddress!=null){
			
			//put in the last 3 IP addresses the secondIpAddress
			properties.setProperty("IP" + (numOfParties-1), secondIpAddress);
			properties.setProperty("IP" + (numOfParties-2), secondIpAddress);
			properties.setProperty("IP" + (numOfParties-3), secondIpAddress);
			
		}
		
		int portNum;
		String ipAddress;
		for(int i=0;i<numOfParties; i++){
			
			OutputStream propOut = null;
			portNum = Integer.parseInt(properties.getProperty("Port" + i));
			ipAddress = properties.getProperty("IP" + i);
			
			
			if(i>0){
				//return the value of the previously changed to its original value
				properties.setProperty("Port" + (i - 1), properties.getProperty("Port" + "0"));
				properties.setProperty("IP" + (i - 1), properties.getProperty("IP" + "0"));
				
			}
				
			properties.setProperty("Port" + i, "" + startPort);
			properties.setProperty("IP" + i, "" + commomIpAddress);
			
			properties.setProperty("Port" + "0", "" + portNum);
			properties.setProperty("IP" + "0", ipAddress);
			
			try {
				  propOut = new FileOutputStream(
				            new File(startFilename + i + ".properties"));
			}catch (Exception e) {
				e.printStackTrace();
			}
			
			try {
				properties.store(propOut, "");
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		
	}

}
