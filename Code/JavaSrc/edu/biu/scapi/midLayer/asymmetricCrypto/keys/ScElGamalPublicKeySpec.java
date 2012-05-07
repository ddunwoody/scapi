package edu.biu.scapi.midLayer.asymmetricCrypto.keys;

import java.security.spec.KeySpec;

import edu.biu.scapi.primitives.dlog.GroupElement;

public class ScElGamalPublicKeySpec implements KeySpec{

	private GroupElement h;
	
	public ScElGamalPublicKeySpec(GroupElement h){
		this.h = h;
	}
	
	public GroupElement getH(){
		return h;
	}
}
