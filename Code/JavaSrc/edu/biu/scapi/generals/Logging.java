/**
 * Project: scapi.
 * Package: edu.biu.scapi.generals.
 * File: Logging.java.
 * Creation date Mar 10, 2011
 * Created by LabTest
 *
 *
 * This class is a singleton class for the logger. We have a single logger for the project.
 */
package edu.biu.scapi.generals;

import java.io.IOException;
import java.util.logging.FileHandler;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

/**
 * @author LabTest
 *
 */
public class Logging {
	
	static Logger logger = Logger.getLogger("Log");
    static FileHandler fh;
	
	static{
		 try {
				fh = new FileHandler("LogFile.log", true);
			} catch (SecurityException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			//we use the simple format
			SimpleFormatter formatter = new SimpleFormatter();
		    fh.setFormatter(formatter);
			logger.addHandler(fh);
			
			//by default we write all the logging levels
			logger.setLevel(Level.ALL);
		    
	}
	
	/**
	 * Sets the logging level.
	 * @param level the required level of logging
	 */
	public static void setLoggingLevel(Level level){
		
		logger.setLevel(level);
	}
	
	/**
	 * return the static Logger.
	 * @return Logger
	 */
	public static Logger getLogger(){
		
		return logger;
	}
	

}
