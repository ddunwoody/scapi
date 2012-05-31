package edu.biu.scapi.midLayer.asymmetricCrypto.keys;

import edu.biu.scapi.primitives.dlog.GroupElement;

public class ScDSAPublicKey implements DSAPublicKey{

	/**
	 * 
	 */
	private static final long serialVersionUID = 7578867149669452105L;
	private GroupElement y;
	
	public ScDSAPublicKey(GroupElement y){
		this.y = y;
	}

	@Override
	public GroupElement getY() {
		return y;
	}

	@Override
	public String getAlgorithm() {
		return "DSA";
	}

	@Override
	public byte[] getEncoded() {
		return null;
	}

	@Override
	public String getFormat() {
		return null;
	}

	
	

}
