/**
* This file is part of SCAPI.
* SCAPI is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
* SCAPI is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
* You should have received a copy of the GNU General Public License along with SCAPI.  If not, see <http://www.gnu.org/licenses/>.
*
* Any publication and/or code referring to and/or based on SCAPI must contain an appropriate citation to SCAPI, including a reference to http://crypto.cs.biu.ac.il/SCAPI.
*
* SCAPI uses Crypto++, Miracl, NTL and Bouncy Castle. Please see these projects for any further licensing issues.
*
*/
package edu.biu.scapi.circuits.encryption;

import javax.crypto.SecretKey;

/**
 * This class is the Key to be used when encrypting with any @link
 * MultiKeyEncryption} scheme. It generalizes the notion of a dual key cipher
 * that is generally associated with Yao's protocol. A dial key cipher uses two
 * keys and is thus only appropriate for encrypting 2-input {@code GarbledGate}
 * s. A MultiKey cipher can be used for any number of inputs. When it is used to
 * encrypt a 2-input {@code GarbledGate}, it is a dial key cipher.
 * {@link MultiKeyEncryptionScheme}. It contains an array of {@link SecretKey}s
 * that the {@link MultiKeyEncryptionScheme} will use to encrypt.
 * 
 * @author Steven Goldfeder
 * 
 */
public class MultiSecretKey {
  private SecretKey[] keys;

  /**
   * A constructor that constructs a {@code MultiSecretKey} from any number of
   * {@code SecretKey} objects. The {@code SecretKey}s can be passed to the
   * constructor either in an array or as separate parameters.
   * 
   * @param keys
   *          The {@code SecretKey}s that will be used to construct the
   *          {@code MultiSecretKey}. The {@code SecretKey}s can be passed to
   *          the constructor either in an array or as separate parameters.
   */
  public MultiSecretKey(SecretKey... keys) {
    this.keys = keys;
  }

  /**
   * An accessor method for getting an array of the {@code SecretKey}s from this
   * {@code MultiSecretKey}.
   * 
   * @return an array containing the individual {@code SecretKey} objects that
   *         make up this {@code MultiSecretKey}
   */
  public SecretKey[] getKeys() {
    return keys;
  }

  /**
   * @return the number of keys in this {@code MultiSecretKey}
   */
  public int numberOfKeys() {
    return keys.length;
  }

}
