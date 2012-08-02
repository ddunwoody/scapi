/**
* This file is part of SCAPI.
* SCAPI is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
* SCAPI is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
* You should have received a copy of the GNU General Public License along with SCAPI.  If not, see <http://www.gnu.org/licenses/>.
*
* Any publication and/or code referring to and/or based on SCAPI must contain an appropriate citation to SCAPI, including a reference to http://crypto.cs.biu.ac.il/SCAPI.
*
* SCAPI uses Crypto++, Miracl, NTL and Bouncy Castle. Please see these projects for any further licensing issues.
*
*/
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
