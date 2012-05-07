package edu.biu.scapi.midLayer.asymmetricCrypto.keys;

import edu.biu.scapi.primitives.dlog.GroupElement;

public class ScElGamalPublicKey implements ElGamalPublicKey {

	private static final long serialVersionUID = 8645777933993577969L;
	private GroupElement h;
	
	public ScElGamalPublicKey(GroupElement h){
		this.h = h;
	}
	
	@Override
	public String getAlgorithm() {
		
		return "ElGamal";
	}

	@Override
	public byte[] getEncoded() {
		return null;
	}

	@Override
	public String getFormat() {
		return null;
	}
	
	public GroupElement getH(){
		return h;
	}

}
