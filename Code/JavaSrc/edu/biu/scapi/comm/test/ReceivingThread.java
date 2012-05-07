/**
 * Project: scapi.
 * Package: edu.biu.scapi.comm.test.
 * File: ReceivingThread.java.
 * Creation date Mar 14, 2011
 * Created by LabTest
 *
 *
 * This file TODO
 */
package edu.biu.scapi.comm.test;

import java.io.IOException;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.comm.Message;

/**
 * @author LabTest
 *
 */
public class ReceivingThread extends Thread {
	
	Channel channel;
	MessageReceiver messageReceiver;
	
	/**
	 * 
	 */
	public ReceivingThread(Channel channel/*, MessageReceiver messageReceiver*/) {
		
		this.channel = channel;
		//this.messageReceiver = messageReceiver;
		
	}
	
	public void run(){
		
		Message msg = null;
		
		while(true){
			try {
				msg = channel.receive();
			} catch (ClassNotFoundException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			//messageReceiver.processMessage(msg);
		}
		
	}

}
