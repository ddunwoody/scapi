Message Authentication Codes
============================

In cryptography, a Message Authentication Code (MAC) is a short piece of information used to authenticate a message and to provide integrity and authenticity assurances on the message. Integrity assurances detect accidental and intentional message changes, while authenticity assurances affirm the message's origin. Scapi provides two implementations of message authentication codes: `CBC-MAC`_ and `HMAC`_.

.. contents::

The Mac Interface
-----------------

This is the general interface for Mac. Every class in this family must implement this interface.

.. java:type:: public interface Mac
   :package: edu.biu.scapi.midLayer.symmetricCrypto.mac

Basic Mac and Verify Functionality
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. java:method:: public byte[] mac(byte[] msg, int offset, int msgLen)
   :outertype: Mac

   Computes the mac operation on the given msg and return the calculated tag.

   :param msg: the message to operate the mac on.
   :param offset: the offset within the message array to take the bytes from.
   :param msgLen: the length of the message in bytes.
   :return: byte[] the return tag from the mac operation.

.. java:method:: public boolean verify(byte[] msg, int offset, int msgLength, byte[] tag)
   :outertype: Mac

   Verifies that the given tag is valid for the given message.

   :param msg: the message to compute the mac on to verify the tag.
   :param offset: the offset within the message array to take the bytes from.
   :param msgLength: the length of the message in bytes.
   :param tag: the tag to verify.
   :return: true if the tag is the result of computing mac on the message. false, otherwise.

Calulcating the Mac when not all the message is known up front
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. java:method:: public void update(byte[] msg, int offset, int msgLen)
   :outertype: Mac

   Adds the byte array to the existing message to mac.

   :param msg: the message to add.
   :param offset: the offset within the message array to take the bytes from.
   :param msgLen: the length of the message in bytes.

.. java:method:: public byte[] doFinal(byte[] msg, int offset, int msgLength)
   :outertype: Mac

   Completes the mac computation and puts the result tag in the tag array.

   :param msg: the end of the message to mac.
   :param offset: the offset within the message array to take the bytes from.
   :param msgLength: the length of the message in bytes.
   :return: the result tag from the mac operation.

Key Handling
~~~~~~~~~~~~

.. java:method:: public SecretKey generateKey(int keySize)
   :outertype: Mac

   Generates a secret key to initialize this mac object.

   :param keySize: is the required secret key size in bits.
   :return: the generated secret key.

.. java:method:: public SecretKey generateKey(AlgorithmParameterSpec keyParams) throws InvalidParameterSpecException
   :outertype: Mac

   Generates a secret key to initialize this mac object.

   :param keyParams: algorithmParameterSpec contains parameters for the key generation of this mac algorithm.
   :throws InvalidParameterSpecException: if the given keyParams does not match this mac algoithm.
   :return: the generated secret key.

.. java:method:: public boolean isKeySet()
   :outertype: Mac

   An object trying to use an instance of mac needs to check if it has already been initialized.

   :return: true if the object was initialized by calling the function setKey.

.. java:method:: public void setKey(SecretKey secretKey) throws InvalidKeyException
   :outertype: Mac

   Sets the secret key for this mac. The key can be changed at any time.

   :param secretKey: secret key
   :throws InvalidKeyException: if the given key does not match this MAC algorithm.

Mac Properties
~~~~~~~~~~~~~~

.. java:method:: public int getMacSize()
   :outertype: Mac

   Returns the input block size in bytes.

   :return: the input block size.

.. _`CBC-MAC`:

CBC-MAC
-------

A **Cipher Block Chaining Message Authentication Code**, abbreviated **CBC-MAC**, is a technique for constructing a message authentication code from a block cipher. The message is processed with some block cipher algorithm in CBC mode to create a chain of blocks such that each block depends on the previous blocks. This interdependence ensures that a change to any of the plaintext bits will cause the final encrypted block to change in a way that cannot be predicted or counteracted without knowing the key to the block cipher. The initialization vector (IV) usually present in CBC encryption is set to zero when a CBC MAC is computed (i.e., there is no IV). In addition, in order for CBC-MAC to be secure for variable-length messages, the length of the message has to be pre-pended to the message in the first block before beginning CBC-MAC. When computed in this way, CBC-MAC is a PRF and thus a secure MAC.

.. note:: We remark that if the length of the message is not known in advance then a different MAC algorithm should be used (for example: HMAC).

The CbcMac Interface
~~~~~~~~~~~~~~~~~~~~

The CbcMac interface is th general interface for CBC-Mac. Every class that implement the CBC-Mac algorithm should implement this interface.

.. java:type:: public interface CbcMac extends UniqueTagMac, PrfVaryingInputLength, UnlimitedTimes
   :package: edu.biu.scapi.midLayer.symmetricCrypto.mac

.. java:method:: public void startMac(int msgLength)
   :outertype: CbcMac

   Pre-pends the length if the message to the message. As a result, the mac will be calculated on [msgLength||msg].

   :param msgLength: the length of the message in bytes.

Basic Usage
~~~~~~~~~~~

.. code-block:: java

    // assume we have a message msg
    byte[] msg;
    
    // initialize a secure random object
    SecureRandom random = new SecureRandom();
    
    // initialize a prp to be used by the CbcMac algorithm
    PseudorandomPermutation prp = new OpenSSLAES(random);
    SecretKey secretKey = prp.generateKey(128);
    prp.setKey(secretKey);
    
    // initialize the CbcMac algorithm
    CbcMac mac = new ScCbcMacPrepending(prp, random);
    
    // calculate the tag on a complete message
    byte[] tag = mac.mac(msg, 0, msg.length);
    
    // compute the mac in stages (in case not all the message is known up front)
    mac.startMac(100);
    mac.update(msg, 0, 20);
    mac.update(msg, 20, 20);
    mac.update(msg, 40, 20);
    mac.update(msg, 60, 20);
    mac.doFinal(msg, 80, 20);

.. _`HMAC`:

HMAC
----

We presented the same HMAC algorithm in the first layer of Scapi. However, there it was only presented as a PRF. In order to make HMAC become also a MAC and not just a PRF, all we have to do is to implement the Mac interface. This means that now our HMAC needs to know how to mac and verify. HMAC is a mac that does not require knowing the length of the message in advance.

The Hmac Interface
~~~~~~~~~~~~~~~~~~

Hmac is a  Marker interface. Every class that implements it is signed as Hmac. Hmac has varying input length and thus implements the interface PrfVaryingInputLength. Currenty the ``BcHMAC`` class implements the ``Hmac`` interface.

.. java:type:: public interface Hmac extends PrfVaryingInputLength, UniqueTagMac, UnlimitedTimes

Basic Usage
~~~~~~~~~~~

Sender usage:

.. code-block:: java

    //Create an hmac object.
    Mac hmac = new BcHMAC("SHA-1");
    
    //Generate a SecretKey
    Hmac.generateKey(128);
    
    //Set the secretKey.
    hmac.setKey(secretKey);
    
    //Get the message to mac and calculate the mac tag.
    byte[] tag = hmac.mac(msg, offset, length); 
    
    //Send the msg and tag to the receiver.
    ...

Receiver usage:

.. code-block:: java

    //Get secretKey, msg and tag byte arrays.
    ...
    //Create the same hmac object as the sender’s hmac object and set the key. 
    ...
    // receive the message and the tag
    ...
    // Verify the tag with the given msg.
    If (hmac.verify(tag, msg, offset, length)) { //Tag is valid.
        //Continue working...
    } else throw new IllegalStateException() //Tag is not valid.
