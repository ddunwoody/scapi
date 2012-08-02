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
