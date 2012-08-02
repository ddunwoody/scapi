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
