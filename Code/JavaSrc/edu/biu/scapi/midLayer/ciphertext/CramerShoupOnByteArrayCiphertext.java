package edu.biu.scapi.midLayer.ciphertext;

import edu.biu.scapi.primitives.dlog.GroupElement;

public class CramerShoupOnByteArrayCiphertext extends CramerShoupCiphertext{

	private byte[] e;
	
	public CramerShoupOnByteArrayCiphertext(GroupElement u1, GroupElement u2, byte[] e, GroupElement v) {
		super(u1, u2, v);
		this.e = e;
		
	}

	public byte[] getE() {
		return e;
	}

}
