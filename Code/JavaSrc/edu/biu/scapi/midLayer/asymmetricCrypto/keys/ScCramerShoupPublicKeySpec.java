package edu.biu.scapi.midLayer.asymmetricCrypto.keys;

import java.security.spec.KeySpec;

import edu.biu.scapi.primitives.dlog.GroupElement;

public class ScCramerShoupPublicKeySpec implements KeySpec {
	private GroupElement c;
	private GroupElement d;
	private GroupElement h;

	
	public ScCramerShoupPublicKeySpec(GroupElement c, GroupElement d, GroupElement h) {
		super();
		this.c = c;
		this.d = d;
		this.h = h;
	}


	public GroupElement getC() {
		return c;
	}


	public GroupElement getD() {
		return d;
	}


	public GroupElement getH() {
		return h;
	}
	
}
