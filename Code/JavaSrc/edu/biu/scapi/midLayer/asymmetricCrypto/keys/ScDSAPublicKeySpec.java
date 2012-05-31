package edu.biu.scapi.midLayer.asymmetricCrypto.keys;

import edu.biu.scapi.primitives.dlog.GroupElement;

public class ScDSAPublicKeySpec {

	private GroupElement y;
	
	public ScDSAPublicKeySpec(GroupElement y){
		this.y = y;
	}

	public GroupElement getY() {
		return y;
	}
}
