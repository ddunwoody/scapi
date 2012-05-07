/**
 * Project: scapi.
 * Package: edu.biu.scapi.comm.test.
 * File: ExecutingThread.java.
 * Creation date Mar 13, 2011
 * Created by LabTest
 *
 *
 * This file TODO
 */
package edu.biu.scapi.comm.test;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;

/**
 * @author LabTest
 *
 */
public class ExecutingThread extends Thread{
	
	String command = null;
	File directory = null;
	
	/**
	 * 
	 */
	public ExecutingThread(String command, String directory) {
		
		
		this.command = command;
		if(directory!=null)
			this.directory = new File(directory);
	}
	
	/**
	 * Run the batch file.
	 */
	public void run() {
	
		Runtime runtime = Runtime.getRuntime() ;
		Process process = null;
		try {
			String fullCommand = "cmd /c start "  + command;
			process = runtime.exec(fullCommand, null, directory) ;
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		PrintWriter out = null;
		try {
			out = new PrintWriter("RunLog.txt");
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    	BufferedReader r = new BufferedReader(
    			new InputStreamReader(process.getInputStream())
    	);
    	String x;
    	int count = 0;
    	try {
			while ((x = r.readLine()) != null) {
				System.out.print("" + ++count + " ");
				System.out.println(x);
				out.println(x);
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    	try {
			r.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    	out.flush();
    	out.close();
		
	}

}
