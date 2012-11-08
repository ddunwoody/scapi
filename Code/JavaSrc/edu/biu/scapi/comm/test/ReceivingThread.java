/**
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
* Copyright (c) 2012 - SCAPI (http://crypto.biu.ac.il/scapi)
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
 * Package: edu.biu.scapi.comm.test.
 * File: ReceivingThread.java.
 * Creation date Mar 14, 2011
 * Created by LabTest
 *
 *
 * This file TODO
 */
package edu.biu.scapi.comm.test;

import java.awt.RenderingHints.Key;
import java.io.IOException;
import java.io.Serializable;
import java.math.BigInteger;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.midLayer.ciphertext.AsymmetricCiphertext;
import edu.biu.scapi.midLayer.plaintext.Plaintext;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.dlog.GroupElementSendableData;
import edu.biu.scapi.primitives.dlog.cryptopp.CryptoPpDlogZpSafePrime;
import edu.biu.scapi.primitives.dlog.groupParams.GroupParams;
import edu.biu.scapi.primitives.dlog.groupParams.ZpGroupParams;
import edu.biu.scapi.tools.Factories.DlogGroupFactory;

/**
 * @author LabTest
 *
 */
public class ReceivingThread extends Thread {
	
	Channel channel;
	//MessageReceiver messageReceiver;
	DlogGroup dlog;
	
	/**
	 * 
	 */
	public ReceivingThread(Channel channel/*, MessageReceiver messageReceiver*/) {
		
		this.channel = channel;
		//this.messageReceiver = messageReceiver;
		
	}
	
	void processMsg(Serializable msg){
		System.out.println("Processing msg");
		if((msg instanceof String) || (msg instanceof BigInteger) || (msg instanceof byte[]) ){
			System.out.println(msg);
		}
		else if(msg instanceof GroupElementSendableData ){
			System.out.println("This is a GroupElementSendableData: " + msg);
		}else if(msg instanceof GroupParams ){
			System.out.println("This is a GroupParams: " + msg);
		} else if (msg instanceof Key){
			System.out.println("This isa key of type: " + msg.getClass());
		}else if (msg instanceof Plaintext) {
			System.out.println("this is a plaintext: " + msg.getClass());
		}else if (msg instanceof AsymmetricCiphertext){
			System.out.println("this is a ciphertext: " + msg.getClass());
		}else {
			System.out.println("this message is something else: " + msg.getClass());
		}
			
	}
	
	void proceessMsgPerformanceTest(Serializable msg){
		if(msg instanceof ZpGroupParams){
			dlog = new CryptoPpDlogZpSafePrime((ZpGroupParams)(msg));
		}
		if(msg instanceof GroupElementSendableData){
			GroupElement gEl = dlog.generateElement(true, (GroupElementSendableData)(msg));
		}
	}
	
		
	public void run(){
		
		//Message msg = null;
		Serializable msg = null;
		//ByteArrayPlaintext msg = null;
		int count = 0;

		long allTimes = 0;
		
		long start = 0;System.currentTimeMillis();
		long stop = 0;
		long duration = 0;
		double runAvgTime = 0;
		BigInteger x = null;
		BigInteger y;
		GroupElement gEl = null;
		
		//hard coded EC group
		try {
			dlog = DlogGroupFactory.getInstance().getObject("DlogECFp(P-224)", "Miracl");
		} catch (FactoriesException e2) {
			// TODO Auto-generated catch block
			e2.printStackTrace();
		}
		
		while(true ){
		//while((count < 30) || !channel.isClosed()){
			//System.out.println("Receiving msg #: " + count);
			try {
				msg =  channel.receive();
				//processMsg(msg);
				if(msg instanceof GroupElementSendableData){
					if(start ==0)
						start = System.currentTimeMillis();
					 gEl = dlog.generateElement(true, (GroupElementSendableData)(msg));
					stop = System.currentTimeMillis();
					duration = stop - start;

					start = stop;
					allTimes += duration;
					count++;
				}else if (msg instanceof BigInteger){
					if( (count % 2) == 0){
						x = (BigInteger)msg;
					}else {
						y = (BigInteger)msg;
						if(start ==0)
							start = System.currentTimeMillis();
						gEl = dlog.generateElement(true, x, y);
						stop = System.currentTimeMillis();
						duration = stop - start;

						start = stop;
						allTimes += duration;
					}
					count++;

				}
				else if(msg instanceof ZpGroupParams){
					dlog = new CryptoPpDlogZpSafePrime((ZpGroupParams)(msg));
				}
				else{
					System.out.println("Got wrong msg: " + msg);
				}
				if((msg instanceof String) && ((String)msg).startsWith("End") ){
					break;
				}
				
				
				
			} catch (ClassNotFoundException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
				try {
					Thread.sleep(30000);
				} catch (InterruptedException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
			}
			
			/*
			try {
				Thread.sleep(1000);
			} catch (InterruptedException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			*/
			//messageReceiver.processMessage(msg);
			//count++;
		}
		runAvgTime = (double)allTimes/(double)count;
		System.out.println("The average running time of receiving a new random element " + count + " times is: " + runAvgTime);
		System.out.println("The last gEl received is:");
		System.out.println(gEl);
	}

}
