Digital Signatures
==================

A digital signature is a mathematical scheme for demonstrating the authenticity of a digital message or document. 
A valid digital signature provides the recipient with a reason to believe that the message was created by a known sender, 
and that it was not altered in transit.

The Digital Signatures family of classes implements three main functionalities that correspond to the cryptographer’s language 
in which an encryption scheme is composed of three algorithms:

1. Generation of the keys.
2. Signing a message.
3. Verifying a signature with a message.

.. contents::

The DigitalSignature Interface
------------------------------

.. java:type:: public interface DigitalSignature
   :package: edu.biu.scapi.midLayer.asymmetricCrypto.digitalSignature

   General interface for digital signatures. Each class of this family must implement this interface. A digital signature is a mathematical scheme for demonstrating the authenticity of a digital message or document. A valid digital signature gives a recipient reason to believe that the message was created by a known sender, and that it was not altered in transit.

Sign and Verify
~~~~~~~~~~~~~~~

.. java:method:: public Signature sign(byte[] msg, int offset, int length) throws KeyException
   :outertype: DigitalSignature

   Signs the given message

   :param msg: the byte array to sign.
   :param offset: the place in the msg to take the bytes from.
   :param length: the length of the msg.
   :throws ArrayIndexOutOfBoundsException: if the given offset and length are wrong for the given message.
   :throws KeyException: if PrivateKey is not set.
   :return: the signatures from the msg signing.

.. java:method:: public boolean verify(Signature signature, byte[] msg, int offset, int length)
   :outertype: DigitalSignature

   Verifies the given signature

   :param signature: to verify
   :param msg: the byte array to verify the signature with
   :param offset: the place in the msg to take the bytes from
   :param length: the length of the msg
   :throws ArrayIndexOutOfBoundsException: if the given offset and length are wrong for the given message.
   :throws IllegalArgumentException: if the given Signature does not match this signature scheme.
   :throws IllegalStateException: if no public key was set.
   :return: true if the signature is valid. false, otherwise.

Key Generation and Handling
~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. java:method:: public KeyPair generateKey(AlgorithmParameterSpec keyParams) throws InvalidParameterSpecException
   :outertype: DigitalSignature

   Generates public and private keys for this digital signature.

   :param keyParams: hold the required key parameters
   :throws InvalidParameterSpecException: if the given keyParams does not match this signature scheme.
   :return: KeyPair holding the public and private keys

.. java:method:: public KeyPair generateKey()
   :outertype: DigitalSignature

   Generates public and private keys for this digital signature.

   :return: KeyPair holding the public and private keys

.. java:method:: public PublicKey getPublicKey()
   :outertype: DigitalSignature

   Returns the PublicKey of this signature scheme.

   This function should not be use to check if the key has been set. To check if the key has been set use isKeySet function.

   :throws IllegalStateException: if no public key was set.
   :return: the PublicKey

.. java:method:: public boolean isKeySet()
   :outertype: DigitalSignature

   Checks if this digital signature object has been given a key already.

   :return: ``true`` if the object has been given a key; ``false`` otherwise.

.. java:method:: public void setKey(PublicKey publicKey, PrivateKey privateKey) throws InvalidKeyException
   :outertype: DigitalSignature

   Sets this digital signature with public key and private key.

   :param publicKey:
   :param privateKey:
   :throws InvalidKeyException: if the given keys do not match this signature scheme.

.. java:method:: public void setKey(PublicKey publicKey) throws InvalidKeyException
   :outertype: DigitalSignature

   Sets this digital signature with a public key.

   In this case the signature object can be used only for verification.

   :param publicKey:
   :throws InvalidKeyException: if the given key does not match his signature scheme.

RSA Based Digital Signature
---------------------------

The RSABasedSignature Interface
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. java:type:: public interface RSABasedSignature extends DigitalSignature, UnlimitedTimes
   :package: edu.biu.scapi.midLayer.asymmetricCrypto.digitalSignature

   General interface for RSA PSS signature scheme. Every concrete implementation of RSA PSS signature should implement this interface. 
   The RSA PSS (Probabilistic Signature Scheme) is a provably secure way of creating signatures with RSA.

BouncyCastle Implementation
~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. java:type:: public class BcRSAPss extends RSAPssAbs
   :package: edu.biu.scapi.midLayer.asymmetricCrypto.digitalSignature

   This class implements the RSA PSS signature scheme, using BC RSAPss implementation. 
   The RSA PSS (Probabilistic Signature Scheme) is a provably secure way of creating signatures with RSA.

.. java:constructor:: public BcRSAPss()
   :outertype: BcRSAPss

   Default constructor. uses default implementations of CryptographicHash and SecureRandom.

.. java:constructor:: public BcRSAPss(CryptographicHash hash, SecureRandom random) throws FactoriesException
   :outertype: BcRSAPss

   Constructor that receives hash and secure random to use.

   :param hash: underlying hash to use.
   :param random: secure random to use.
   :throws FactoriesException: if there is no hash with the given name.

Crypto++ Implementation
~~~~~~~~~~~~~~~~~~~~~~~

.. java:type:: public class CryptoPPRSAPss extends RSAPssAbs
   :package: edu.biu.scapi.midLayer.asymmetricCrypto.digitalSignature

   This class implements the RSA PSS signature scheme, using Crypto++ RSAPss implementation. 
   The RSA PSS (Probabilistic Signature Scheme) is a provably secure way of creating signatures with RSA.

.. java:constructor:: public CryptoPPRSAPss()
   :outertype: CryptoPPRSAPss

   Default constructor. uses default implementation of SecureRandom.

.. java:constructor:: public CryptoPPRSAPss(SecureRandom random)
   :outertype: CryptoPPRSAPss

   Constructor that receives the secure random object to use.

   :param random: secure random to use

OpenSSL Implementation
~~~~~~~~~~~~~~~~~~~~~~

.. java:type:: public class OpenSSLRSAPss extends RSAPssAbs
   :package: edu.biu.scapi.midLayer.asymmetricCrypto.digitalSignature

   This class implements the RSA PSS signature scheme, using OpenSSL RSAPss implementation. The RSA PSS (Probabilistic Signature Scheme) is a provably secure way of creating signatures with RSA.

.. java:constructor:: public OpenSSLRSAPss()
   :outertype: OpenSSLRSAPss

   Default constructor. uses default implementation of SecureRandom.

.. java:constructor:: public OpenSSLRSAPss(SecureRandom random)
   :outertype: OpenSSLRSAPss

   Constructor that receives the secure random object to use.

   :param random: secure random to use

Example of Usage
~~~~~~~~~~~~~~~~

Sender usage:

.. code-block:: java

    //Create an RSAPss signature object.
    RSAPss signer = new BcRSAPss();
    
    //Generate a keyPair using the RSAPss object.
    KeyPair pair = signer.generateKey(new RSAKeyGenParameterSpec(1024, null)); 
    
    //Generate a keyPair using the signer.
    KeyPair pair = signer.generateKey();
    
    //Publish your public key.
    Publish(pair.getPublic());
    
    //Set private key and party2's public key: 
    signer.setKey(party2PublicKey, pair.getPrivate());
    
    //Get a byte[] message to sign, and sign it.
    Signature signature= signer.sign(msg, offset, length); //Send signature, msg and keys to the receiver.

Receiver usage:

.. code-block:: java

    //Create the same RSAPss object as the sender’s object. 
    //Generate a keyPair using the signer object.
    KeyPair pair = signer.generateKey();
    
    //Publish your public key.
    Publish(pair.getPublic());
    
    //Set private key and party1's public key: 
    signer.setKey(party1PublicKey, pair.getPrivate());
    
    //Get the signature and message and verify it.
    ...
    
    if (!signer.verify(signature, msg, offset, length)) {
        Throw new IllegalArgumentException(“the message is not verified!”);
    }
    
    //Message verified, continue working with it.
    ...

DSA Digital Signature
---------------------

The DSABasedSignature Interface
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. java:type:: public interface DSABasedSignature extends DigitalSignature, UnlimitedTimes
   :package: edu.biu.scapi.midLayer.asymmetricCrypto.digitalSignature

   General interface for DSA signature scheme. Every concrete implementation of DSA signature should implement this interface.

Scapi Implementation
~~~~~~~~~~~~~~~~~~~~

.. java:type:: public class ScDSA implements DSABasedSignature
   :package: edu.biu.scapi.midLayer.asymmetricCrypto.digitalSignature

   This class implements the DSA signature scheme.

.. java:constructor:: public ScDSA()
   :outertype: ScDSA

   Default constructor. uses default implementations of CryptographicHash, DlogGroup and SecureRandom.

.. java:constructor:: public ScDSA(CryptographicHash hash, DlogGroup dlog, SecureRandom random)
   :outertype: ScDSA

   Constructor that receives hash, dlog and secure random to use.

   :param hash: underlying hash to use.
   :param dlog: underlying DlogGroup to use.
   :param random: secure random to use.

OpenSSL Implementation
~~~~~~~~~~~~~~~~~~~~~~

.. java:type:: public class OpenSSLDSA implements DSABasedSignature
   :package: edu.biu.scapi.midLayer.asymmetricCrypto.digitalSignature

   This class implements the DSA signature scheme using OpenSSL library.

.. java:constructor:: public OpenSSLDSA()
   :outertype: OpenSSLDSA

   Default constructor. uses default implementations of DlogGroup.

.. java:constructor:: public OpenSSLDSA(DlogGroup dlog)
   :outertype: OpenSSLDSA

   Constructor that receives a dlog to use.

   :param dlog: underlying DlogGroup to use.

Example of Usage
~~~~~~~~~~~~~~~~

Sender usage:

.. code-block:: java

    //Create a DSA signature object.
    DSA signer = new ScDSA(new MiraclDlogECFp());
    
    //Generate a keyPair using the DSA object.
    KeyPair pair = signer.generateKey();
    
    //Publish your public key.
    Publish(pair.getPublic());
    
    //Set private key and party2's public key: 
    signer.setKey(party2PublicKey, pair.getPrivate());
    
    //Get a byte[] message to sign, and sign it.
    Signature signature= signer.sign(msg, offset, length); 
    
    //Send signature, msg and keys to the receiver.
    ...

Receiver usage:

.. code-block:: java

    //Create the same DSA object as the sender’s object. 
    //Generate a keyPair using the signer object.
    KeyPair pair = signer.generateKey();
    
    //Publish your public key.
    Publish(pair.getPublic());
    
    //Set private key and party1's public key: 
    signer.setKey(party1PublicKey, pair.getPrivate());
    
    //Get the signature and message and verify it.
    ...
    
    if (!signer.verify(signature, msg, offset, length)) {
        throw new IllegalArgumentException(“the message is not verified!”);
    }
    
    //Message verified, continue working with it.
    ...
