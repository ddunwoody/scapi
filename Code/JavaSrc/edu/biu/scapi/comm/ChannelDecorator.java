/**
 * 
 */
package edu.biu.scapi.comm;

/** 
  * @author LabTest
 */
public abstract class ChannelDecorator implements Channel {
	protected Channel channel;
	

	/**
	 * 
	 * @param channel 
	 */
	public ChannelDecorator(Channel channel) {
		this.channel = channel;
	}
	
}