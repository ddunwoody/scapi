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
