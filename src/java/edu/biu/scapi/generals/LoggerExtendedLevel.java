/**
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
* Copyright (c) 2012 - SCAPI (http://crypto.biu.ac.il/scapi)
* This file is part of the SCAPI project.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
* 
* Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"),
* to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
* and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
* 
* The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
* 
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
* FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
* WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
* 
* We request that any publication and/or code referring to and/or based on SCAPI contain an appropriate citation to SCAPI, including a reference to
* http://crypto.biu.ac.il/SCAPI.
* 
* SCAPI uses Crypto++, Miracl, NTL and Bouncy Castle. Please see these projects for any further licensing issues.
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
*/


/**
 * Project: scapi.
 * Package: edu.biu.scapi.generals.
 * File: LoggerExtendedLevel.java.
 * Creation date Mar 13, 2011
 * Created by LabTest
 *
 *
 * This class extends the Level class of the logger. The aim is to generate additional levels that will
 * suite the scapi project. For example, we create a TIMING level who's aim is to log only timing records
 * and thus must have a higher level than severe. 
 */
package edu.biu.scapi.generals;

import java.util.logging.Level;

/**
 * @author LabTest
 * 
 */
public class LoggerExtendedLevel extends Level {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	// Create the new level
    public static final Level TIMING = new LoggerExtendedLevel("TIMING", Level.SEVERE.intValue()+10);

    /**
     * 
     * @param name the name of the level
     * @param value the int value of the level.
     */
    public LoggerExtendedLevel(String name, int value) {
        super(name, value);
    }


}
