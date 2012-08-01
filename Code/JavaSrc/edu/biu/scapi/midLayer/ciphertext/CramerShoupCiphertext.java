package edu.biu.scapi.midLayer.ciphertext;

import edu.biu.scapi.primitives.dlog.GroupElement;

public abstract class CramerShoupCiphertext implements AsymmetricCiphertext{

	private GroupElement u1;
	private GroupElement u2;
	private GroupElement v;
	
	public CramerShoupCiphertext(GroupElement u1, GroupElement u2, GroupElement v) {
		this.u1 = u1;
		this.u2 = u2;
		this.v = v;
	}

	public GroupElement getU1() {
		return u1;
	}

	public GroupElement getU2() {
		return u2;
	}

	public GroupElement getV() {
		return v;
	}
}
