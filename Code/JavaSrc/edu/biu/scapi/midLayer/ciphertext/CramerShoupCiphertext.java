package edu.biu.scapi.midLayer.ciphertext;

import edu.biu.scapi.primitives.dlog.GroupElement;

/**
 * This class is a container that encapsulates the cipher data resulting from applying the CramerShoupDDH encryption.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class CramerShoupCiphertext implements Ciphertext {
	private GroupElement u1;
	private GroupElement u2;
	private GroupElement e;
	private GroupElement v;
	
	public CramerShoupCiphertext(GroupElement u1, GroupElement u2, GroupElement e, GroupElement v) {
		super();
		this.u1 = u1;
		this.u2 = u2;
		this.e = e;
		this.v = v;
	}

	public GroupElement getU1() {
		return u1;
	}

	public GroupElement getU2() {
		return u2;
	}

	public GroupElement getE() {
		return e;
	}

	public GroupElement getV() {
		return v;
	}
	
	
	
}
