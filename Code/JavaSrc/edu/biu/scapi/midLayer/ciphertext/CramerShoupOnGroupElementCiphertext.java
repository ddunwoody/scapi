package edu.biu.scapi.midLayer.ciphertext;

import edu.biu.scapi.primitives.dlog.GroupElement;

/**
 * This class is a container that encapsulates the cipher data resulting from applying the CramerShoupDDH encryption.
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
 *
 */
public class CramerShoupOnGroupElementCiphertext extends CramerShoupCiphertext {
	
	private GroupElement e;
	
	public CramerShoupOnGroupElementCiphertext(GroupElement u1, GroupElement u2, GroupElement e, GroupElement v) {
		super(u1, u2, v);
		this.e = e;
	}

	public GroupElement getE() {
		return e;
	}
	
}
