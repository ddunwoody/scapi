package edu.biu.scapi.midLayer.plaintext;

import edu.biu.scapi.primitives.dlog.GroupElement;

/**
 * This class holds the plaintext as a GroupElement.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class GroupElementPlaintext implements Plaintext{

	private GroupElement element;
	
	public GroupElementPlaintext(GroupElement el){
		element = el;
	}
	
	public GroupElement getElement(){
		return element;
	}
	
	@Override
	public boolean equals(Object plaintext){
		if (!(plaintext instanceof GroupElementPlaintext)){
			return false;
		}
		GroupElement el = ((GroupElementPlaintext) plaintext).getElement();
		
		if (!element.equals(el)){
			return false;
		} 
		
		return true;
	}
}
