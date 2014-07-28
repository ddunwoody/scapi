Asymmetric Encryption
=====================

Asymmetric encryption refers to a cryptographic system requiring two separate keys, one to encrypt the plaintext, and one to decrypt the ciphertext. Neither key will do both functions. One of these keys is public and the other is kept private. If the encryption key is the one published then the system enables private communication from the public to the decryption key's owner.

.. contents::

Asymmetric encryption can be used by a protocol or a user in two different ways:

1. The protocol works on an abstract level and does not know the concrete algorithm of the asymmetric encryption. This way the protocol cannot create a specific Plaintext to the encrypt function because it does not know which concrete Plaintext the encrypt function should get.
Similarly, the protocol does not know how to treat the Plaintext returned from the decrypt function.
In these cases the protocol has a byte array that needs to be encrypted.

2. The protocol knows the concrete algorithm of the asymmetric encryption. This way the protocol knows which Plaintext implementation the encrypt function gets and the decrypt function returns. Therefore, the protocol can be specific and cast the plaintext to the concrete implementation. For example, the protocol knows that it has a DamgardJurikEnc object, so the encrypt function gets a BigIntegerPlaintext and the decrypt function returns a BigIntegerPlaintext. The protocol can create such a plaintext in order to call the encrypt function or cast the returned plaintext from the decrypt function to get the BigInteger value that was encrypted.

The AsymmetricEnc Interface
---------------------------

.. java:type:: public interface AsymmetricEnc extends Cpa, Indistinguishable
   :package: edu.biu.scapi.midLayer.asymmetricCrypto.encryption

   General interface for asymmetric encryption. Each class of this family must implement this interface.

Encryption and Decryption
~~~~~~~~~~~~~~~~~~~~~~~~~

.. java:method:: public AsymmetricCiphertext encrypt(Plaintext plainText)
   :outertype: AsymmetricEnc

   Encrypts the given plaintext using this asymmetric encryption scheme.

   :param plainText: message to encrypt
   :throws IllegalArgumentException: if the given Plaintext doesn't match this encryption type.
   :throws IllegalStateException: if no public key was set.
   :return: Ciphertext the encrypted plaintext

.. java:method:: public Plaintext decrypt(AsymmetricCiphertext cipher) throws KeyException
   :outertype: AsymmetricEnc

   Decrypts the given ciphertext using this asymmetric encryption scheme.

   :param cipher: ciphertext to decrypt
   :throws IllegalArgumentException: if the given Ciphertext doesn't march this encryption type.
   :throws KeyException: if there is no private key
   :return: Plaintext the decrypted cipher


Plaintext Manipulation
~~~~~~~~~~~~~~~~~~~~~~

.. java:method:: public Plaintext generatePlaintext(byte[] text)
   :outertype: AsymmetricEnc

   Generates a Plaintext suitable for this encryption scheme from the given message.

   A Plaintext object is needed in order to use the encrypt function. Each encryption scheme might generate a different type of Plaintext according to what it needs for encryption. The encryption function receives as argument an object of type Plaintext in order to allow a protocol holding the encryption scheme to be oblivious to the exact type of data that needs to be passed for encryption.

   :param text: byte array to convert to a Plaintext object.
   :throws IllegalArgumentException: if the given message's length is greater than the maximum.

.. java:method:: public byte[] generateBytesFromPlaintext(Plaintext plaintext)
   :outertype: AsymmetricEnc

   Generates a byte array from the given plaintext. This function should be used when the user does not know the specific type of the Asymmetric encryption he has, and therefore he is working on byte array.

   :param plaintext: to generates byte array from.
   :return: the byte array generated from the given plaintext.

.. java:method:: public int getMaxLengthOfByteArrayForPlaintext() throws NoMaxException
   :outertype: AsymmetricEnc

   Returns the maximum size of the byte array that can be passed to generatePlaintext function. This is the maximum size of a byte array that can be converted to a Plaintext object suitable to this encryption scheme.

   :throws NoMaxException: if this encryption scheme has no limit on the plaintext input.
   :return: the maximum size of the byte array that can be passed to generatePlaintext function.

.. java:method:: public boolean hasMaxByteArrayLengthForPlaintext()
   :outertype: AsymmetricEnc

   There are some encryption schemes that have a limit of the byte array that can be passed to the generatePlaintext. This function indicates whether or not there is a limit. Its helps the user know if he needs to pass an array with specific length or not.

   :return: true if this encryption scheme has a maximum byte array length to generate a plaintext from; false, otherwise.

Key Generation
~~~~~~~~~~~~~~

.. java:method:: public KeyPair generateKey(AlgorithmParameterSpec keyParams) throws InvalidParameterSpecException
   :outertype: AsymmetricEnc

   Generates public and private keys for this asymmetric encryption.

   :param keyParams: hold the required parameters to generate the encryption scheme's keys
   :throws InvalidParameterSpecException: if the given parameters don't match this encryption scheme.
   :return: KeyPair holding the public and private keys relevant to the encryption scheme

.. java:method:: public KeyPair generateKey()
   :outertype: AsymmetricEnc

   Generates public and private keys for this asymmetric encryption.

   :return: KeyPair holding the public and private keys

Key Handling
~~~~~~~~~~~~

.. java:method:: public PublicKey getPublicKey()
   :outertype: AsymmetricEnc

   Returns the PublicKey of this encryption scheme.

   This function should not be use to check if the key has been set. To check if the key has been set use isKeySet function.

   :throws IllegalStateException: if no public key was set.
   :return: the PublicKey

.. java:method:: public boolean isKeySet()
   :outertype: AsymmetricEnc

   Checks if this AsymmetricEnc object has been previously initialized with corresponding keys.

   :return: ``true`` if either the Public Key has been set or the key pair (Public Key, Private Key) has been set; ``false`` otherwise.

.. java:method:: public void setKey(PublicKey publicKey, PrivateKey privateKey) throws InvalidKeyException
   :outertype: AsymmetricEnc

   Sets this asymmetric encryption with public key and private key.

   :param publicKey:
   :param privateKey:
   :throws InvalidKeyException: if the given keys don't match this encryption scheme.

.. java:method:: public void setKey(PublicKey publicKey) throws InvalidKeyException
   :outertype: AsymmetricEnc

   Sets this asymmetric encryption with a public key

   In this case the encryption object can be used only for encryption.

   :param publicKey:
   :throws InvalidKeyException: if the given key doesn't match this encryption scheme.

Reconstruction (from communication channel)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. java:method:: public AsymmetricCiphertext reconstructCiphertext(AsymmetricCiphertextSendableData data)
   :outertype: AsymmetricEnc

   Reconstructs a suitable AsymmetricCiphertext from data that was probably obtained via a Channel or any other means of sending data (including serialization).

   We emphasize that this is NOT in any way an encryption function, it just receives ENCRYPTED DATA and places it in a ciphertext object.

   :param data: contains all the necessary information to construct a suitable ciphertext.
   :return: the AsymmetricCiphertext that corresponds to the implementing encryption scheme, for ex: CramerShoupCiphertext

.. java:method:: public PrivateKey reconstructPrivateKey(KeySendableData data)
   :outertype: AsymmetricEnc

   Reconstructs a suitable PrivateKey from data that was probably obtained via a Channel or any other means of sending data (including serialization).

   We emphasize that this function does NOT in any way generate a key, it just receives data and recreates a PrivateKey object.

   :param data: a KeySendableData object needed to recreate the original key. The actual type of KeySendableData has to be suitable to the actual encryption scheme used, otherwise it throws an IllegalArgumentException
   :return: a new PrivateKey with the data obtained as argument

.. java:method:: public PublicKey reconstructPublicKey(KeySendableData data)
   :outertype: AsymmetricEnc

   Reconstructs a suitable PublicKey from data that was probably obtained via a Channel or any other means of sending data (including serialization).

   We emphasize that this function does NOT in any way generate a key, it just receives data and recreates a PublicKey object.

   :param data: a KeySendableData object needed to recreate the original key. The actual type of KeySendableData has to be suitable to the actual encryption scheme used, otherwise it throws an IllegalArgumentException
   :return: a new PublicKey with the data obtained as argument

Using the Generic Interface
---------------------------

Sender Usage:

.. code-block:: java

    //Get an abstract Asymmetric encryption object from somewhere. //Generate a keyPair using the encryptor.
    KeyPair pair = encryptor.generateKey();

    //Publish your public key.
    Publish(pair.getPublic());

    //Set private key and party2's public key: 
    encryptor.setKey(party2PublicKey, pair.getPrivate());
    
    //Generate a plaintext suitable for this encryption object using the encryption object.
    Plaintext plaintext = encryptor.generatePlaintext(msg);

    //Encrypt the plaintext
    AsymmetricCiphertext cipher = encryptor.encrypt(plaintext);

    //Send cipher and keys to the receiver.
    ...

Receiver Usage:

.. code-block:: java

    //Get the same asymmetric encryption object as the sender’s object. //Generate a keyPair using the encryption object.
    KeyPair pair = encryptor.generateKey();

    //Publish your public key.
    Publish(pair.getPublic());

    //Set private key and party1's public key: 
    encryptor.setKey(party1PublicKey, pair.getPrivate());
    
    //Get the ciphertext and decrypt it to get the plaintext.
    ...

    Plaintext plaintext = encryptor.decrypt(cipher);
    //Get the plaintext bytes using the encryption object and use it as needed. 
    byte[] text = encryptor.generatesBytesFromPlaintext(plaintext);
    ...

El Gamal Encryption Scheme
--------------------------

The El Gamal encryption scheme’s security is based on the hardness of the decisional Diffie-Hellman (DDH) problem. ElGamal encryption can be defined over any cyclic group :math:`G`. Its security depends upon the difficulty of a certain problem in :math:`G` related to computing discrete logarithms. We implement El Gamal over a Dlog Group :math:`(G, q, g)` where :math:`q` is the order of group :math:`G` and :math:`g` is the generator.

ElGamal encryption scheme can encrypt a group element and a byte array. The general case that accepts a message that should be encrypted usually uses the encryption on a byte array, but in other cases there are protocols that do multiple calculations and might want to keep working on a close group. For those cases we provide encryption on a group element.

In order to allow these two encryption types, we provide two ElGamal concrete classes. One implements the encrypt function on a group element and is called :java:ref:`ScElGamalOnGroupElement`, and the other one implements the encrypt function on a byte array and is called :java:ref:`ScElGamalOnByteArray`.

.. note:: Note that ElGamal on a groupElement is an asymmetric multiplicative homomorphic encryption, while ElGamal on a ByteArray is not.

ElGamalEnc Interface
~~~~~~~~~~~~~~~~~~~~

.. java:type:: public interface ElGamalEnc extends AsymmetricEnc
   :package: edu.biu.scapi.midLayer.asymmetricCrypto.encryption

   General interface for El Gamal encryption scheme. Every concrete implementation of ElGamal should implement this interface. By definition, this encryption scheme is CPA-secure and Indistinguishable.

.. java:method:: public AsymmetricCiphertext encryptWithGivenRandomValue(Plaintext plaintext, BigInteger y)
   :outertype: ElGamalEnc

   Encrypts the given message using ElGamal encryption scheme.

   :param plaintext: contains message to encrypt. The given plaintext must match this ElGamal type.
   :throws IllegalArgumentException: if the given Plaintext does not match this ElGamal type.
   :throws IllegalStateException: if no public key was set.
   :return: Ciphertext containing the encrypted message.

ScElGamalOnByteArray Interface
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. java:type:: public class ScElGamalOnByteArray extends ElGamalAbs
   :package: edu.biu.scapi.midLayer.asymmetricCrypto.encryption

   This class performs the El Gamal encryption scheme that perform the encryption on a ByteArray. The general encryption of a message usually uses this type of encryption. By definition, this encryption scheme is CPA-secure and Indistinguishable.

Constructors
^^^^^^^^^^^^

.. java:constructor:: public ScElGamalOnByteArray()
   :outertype: ScElGamalOnByteArray

   Default constructor. Uses the default implementations of DlogGroup and SecureRandom.

.. java:constructor:: public ScElGamalOnByteArray(DlogGroup dlogGroup, KeyDerivationFunction kdf) throws SecurityLevelException
   :outertype: ScElGamalOnByteArray

   Constructor that gets a DlogGroup and sets it to the underlying group. It lets SCAPI choose and source of randomness.

   :param dlogGroup: must be DDH secure.
   :param kdf: a key derivation function.
   :throws SecurityLevelException: if the given dlog group does not have DDH security level.

.. java:constructor:: public ScElGamalOnByteArray(DlogGroup dlogGroup, KeyDerivationFunction kdf, SecureRandom random) throws SecurityLevelException
   :outertype: ScElGamalOnByteArray

   Constructor that gets a DlogGroup and source of randomness.

   :param dlogGroup: must be DDH secure.
   :param kdf: a key derivation function.
   :param random: source of randomness.
   :throws SecurityLevelException: if the given dlog group does not have DDH security level.

Complete Encryption
^^^^^^^^^^^^^^^^^^^

.. java:method:: protected AsymmetricCiphertext completeEncryption(GroupElement c1, GroupElement hy, Plaintext plaintext)
   :outertype: ScElGamalOnByteArray

   Completes the encryption operation.

   :param plaintext: contains message to encrypt. MUST be of type ByteArrayPlaintext.
   :throws IllegalArgumentException: if the given Plaintext is not an instance of ByteArrayPlaintext.
   :return: Ciphertext of type ElGamalOnByteArrayCiphertext containing the encrypted message.

ScElGamalOnGroupElement Interface
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. java:type:: public class ScElGamalOnGroupElement extends ElGamalAbs implements AsymMultiplicativeHomomorphicEnc
   :package: edu.biu.scapi.midLayer.asymmetricCrypto.encryption

   This class performs the El Gamal encryption scheme that perform the encryption on a GroupElement.

   In some cases there are protocols that do multiple calculations and might want to keep working on a close group. For those cases we provide encryption on a group element. By definition, this encryption scheme is CPA-secure and Indistinguishable.

Constructors
^^^^^^^^^^^^

.. java:constructor:: public ScElGamalOnGroupElement()
   :outertype: ScElGamalOnGroupElement

   Default constructor. Uses the default implementations of DlogGroup, CryptographicHash and SecureRandom.

.. java:constructor:: public ScElGamalOnGroupElement(DlogGroup dlogGroup) throws SecurityLevelException
   :outertype: ScElGamalOnGroupElement

   Constructor that gets a DlogGroup and sets it to the underlying group. It lets SCAPI choose and source of randomness.

   :param dlogGroup: must be DDH secure.
   :throws SecurityLevelException:

.. java:constructor:: public ScElGamalOnGroupElement(DlogGroup dlogGroup, SecureRandom random) throws SecurityLevelException
   :outertype: ScElGamalOnGroupElement

   Constructor that gets a DlogGroup and source of randomness.

   :param dlogGroup: must be DDH secure.
   :param random: source of randomness.
   :throws SecurityLevelException: if the given dlog group does not have DDH security level.

Complete Encryption
^^^^^^^^^^^^^^^^^^^

.. java:method:: protected AsymmetricCiphertext completeEncryption(GroupElement c1, GroupElement hy, Plaintext plaintext)
   :outertype: ScElGamalOnGroupElement

   Completes the encryption operation.

   :param plaintext: contains message to encrypt. MUST be of type GroupElementPlaintext.
   :throws IllegalArgumentException: if the given Plaintext is not an instance of GroupElementPlaintext.
   :return: Ciphertext of type ElGamalOnGroupElementCiphertext containing the encrypted message.

Multiply Ciphertexts (Homomorphic Encryption operation)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. java:method:: public AsymmetricCiphertext multiply(AsymmetricCiphertext cipher1, AsymmetricCiphertext cipher2)
   :outertype: ScElGamalOnGroupElement

   Calculates the ciphertext resulting of multiplying two given ciphertexts. Both ciphertexts have to have been generated with the same public key and DlogGroup as the underlying objects of this ElGamal object.

   :throws IllegalArgumentException: in the following cases: 1. If one or more of the given ciphertexts is not instance of ElGamalOnGroupElementCiphertext. 2. If one or more of the GroupElements in the given ciphertexts is not a member of the underlying DlogGroup of this ElGamal encryption scheme.
   :throws IllegalStateException: if no public key was set.
   :return: Ciphertext of the multiplication of the plaintexts p1 and p2 where alg.encrypt(p1)=cipher1 and alg.encrypt(p2)=cipher2

Basic Usage
~~~~~~~~~~~

Sender usage:

.. code-block:: java

    //Create an underlying DlogGroup.
    DlogGroup dlog = new MiraclDlogECFp();
    
    //Create an ElGamalOnGroupElement encryption object.
    ElGamalEnc elGamal = new ScElGamalOnGroupElement(dlog);
    
    //Generate a keyPair using the ElGamal object.
    KeyPair pair = elGamal.generateKey();
    
    //Publish your public key.
    Publish(pair.getPublic());
    
    //Set private key and party2's public key: 
    elGamal.setKey(party2PublicKey, pair.getPrivate());
    
    //Create a GroupElementPlaintext to encrypt and encrypt the plaintext.
    Plaintext plaintext = new GroupElementPlaintext(dlog.createRandomElement()); 
    AsymmetricCiphertext cipher = elGamal.encrypt(plaintext); 
    
    //Sends cipher to the receiver.
    
Receiver usage:

.. code-block:: java

    //Create an ElGamal object with the same DlogGroup definition as party1. 
    //Generate a keyPair using the ElGamal object.
    KeyPair pair = elGamal.generateKey();
    
    //Publish your public key.
    Publish(pair.getPublic());
    
    //Set private key and party1's public key: 
    elGamal.setKey(party1PublicKey, pair.getPrivate());
    
    //Get the ciphertext and decrypt it to get the plaintext. ...
    GroupElementPlaintext plaintext = (GroupElementPlaintext)elGamal.decrypt(cipher);
    
    //Get the plaintext element and use it as needed.
    GroupElement element = plaintext.getElement(); ...

Cramer Shoup DDH Encryption Scheme
----------------------------------

The Cramer Shoup encryption scheme’s security is based on the hardness of the decisional Diffie-Hellman (DDH) problem, 
like El Gamal encryption scheme. Cramer Shoup encryption can be defined over any cyclic group :math:`G`. 
Its security depends upon the difficulty of a certain problem in :math:`G` related to computing discrete logarithms. 

We implement Cramer Shoup over a Dlog Group :math:`(G, q, g)` where :math:`q` is the order of group :math:`G` and :math:`g` is the generator.

In contrast to El Gamal, which is extremely malleable, Cramer–Shoup adds other elements to ensure non-malleability even against a resourceful attacker. This non-malleability is achieved through the use of a hash function and additional computations, resulting in a ciphertext which is twice as large as in El Gamal.

Similary to ElGamal, Cramer Shoup encryption scheme can encrypt a group element and a byte array.
In order to allow these two encryption types, we provide two Cramer Shoup concrete classes. 
One implements the encrypt function on a group element and is called :java:ref:`ScCramerShoupDDHOnGroupElement`, 
and the other one implements the encrypt function on a byte array and is called :java:ref:`ScCramerShoupDDHOnByteArray`.

The CramerShoupDDHEnc Interface
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. java:type:: public interface CramerShoupDDHEnc extends AsymmetricEnc, Cca2
   :package: edu.biu.scapi.midLayer.asymmetricCrypto.encryption

   General interface for CramerShoup encryption scheme. Every concrete implementation of CramerShoup encryption should implement this interface. By definition, this encryption scheme is CCA-secure and NonMalleable.

The ScCramerShoupDDHOnByteArray Interface
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. java:type:: public class ScCramerShoupDDHOnByteArray extends CramerShoupAbs
   :package: edu.biu.scapi.midLayer.asymmetricCrypto.encryption

.. java:constructor:: public ScCramerShoupDDHOnByteArray()
   :outertype: ScCramerShoupDDHOnByteArray

   Default constructor. It uses a default Dlog group and CryptographicHash.

.. java:constructor:: public ScCramerShoupDDHOnByteArray(DlogGroup dlogGroup, CryptographicHash hash, KeyDerivationFunction kdf) throws SecurityLevelException
   :outertype: ScCramerShoupDDHOnByteArray

   Constructor that lets the user choose the underlying dlog and hash. Uses default implementation of SecureRandom as source of randomness.

   :param dlogGroup: underlying DlogGroup to use, it has to have DDH security level
   :param hash: underlying hash to use, has to have CollisionResistant security level
   :throws SecurityLevelException: if the Dlog Group or the Hash function do not meet the required Security Level

.. java:constructor:: public ScCramerShoupDDHOnByteArray(DlogGroup dlogGroup, CryptographicHash hash, KeyDerivationFunction kdf, SecureRandom random) throws SecurityLevelException
   :outertype: ScCramerShoupDDHOnByteArray

   Constructor that lets the user choose the underlying dlog, hash and source of randomness.

   :param dlogGroup: underlying DlogGroup to use, it has to have DDH security level
   :param hash: underlying hash to use, has to have CollisionResistant security level
   :param random: source of randomness.
   :throws SecurityLevelException: if the Dlog Group or the Hash function do not meet the required Security Level

The ScCramerShoupDDHOnGroupElement Interface
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. java:type:: public class ScCramerShoupDDHOnGroupElement extends CramerShoupAbs
   :package: edu.biu.scapi.midLayer.asymmetricCrypto.encryption

   Concrete class that implement Cramer-Shoup encryption scheme. By definition, this encryption scheme is CCA-secure and NonMalleable.

.. java:constructor:: public ScCramerShoupDDHOnGroupElement()
   :outertype: ScCramerShoupDDHOnGroupElement

   Default constructor. It uses a default Dlog group and CryptographicHash.

.. java:constructor:: public ScCramerShoupDDHOnGroupElement(DlogGroup dlogGroup, CryptographicHash hash) throws SecurityLevelException
   :outertype: ScCramerShoupDDHOnGroupElement

   Constructor that lets the user choose the underlying dlog and hash. Uses default implementation of SecureRandom as source of randomness.

   :param dlogGroup: underlying DlogGroup to use, it has to have DDH security level
   :param hash: underlying hash to use, has to have CollisionResistant security level
   :throws SecurityLevelException: if the Dlog Group or the Hash function do not meet the required Security Level

.. java:constructor:: public ScCramerShoupDDHOnGroupElement(DlogGroup dlogGroup, CryptographicHash hash, SecureRandom random) throws SecurityLevelException
   :outertype: ScCramerShoupDDHOnGroupElement

   Constructor that lets the user choose the underlying dlog, hash and source of randomness.

   :param dlogGroup: underlying DlogGroup to use, it has to have DDH security level
   :param hash: underlying hash to use, has to have CollisionResistant security level
   :param random: source of randomness.
   :throws SecurityLevelException: if the Dlog Group or the Hash function do not meet the required Security Level

Basic Usage
~~~~~~~~~~~

Sender usage:

.. code-block:: java

    //Create an underlying DlogGroup.
    DlogGroup dlog = new MiraclDlogECF2m();
    
    //Create a CramerShoupOnByteArray encryption object.
    CramerShoupDDHEnc encryptor = new ScCramerShoupDDHOnByteArray(dlog);
    
    //Generate a keyPair using the CramerShoup object.
    KeyPair pair = encryptor.generateKey();
    
    //Publish your public key.
    Publish(pair.getPublic());
    
    //Set private key and party2's public key: 
    encryptor.setKey(party2PublicKey, pair.getPrivate());
    
    //Get a byte[] message to encrypt. Check if the length of the given msg is valid.
    if (encryptor.hasMaxByteArrayLengthForPlaintext()){
        if (msg.length>encryptor.getMaxLengthOfByteArrayForPlaintext()) {
    	    throw new IllegalArgumentException(“message too long”);
        }
    }
    
    //Generate a plaintext suitable to this CramerShoup object.
    Plaintext plaintext = encryptor.generatePlaintext(msg);
    
    //Encrypt the plaintext
    AsymmetricCiphertext cipher = encrypor.encrypt(plaintext);
    
    //Send cipher and keys to the receiver.

Receiver usage:

.. code-block:: java

    //Create a CramerShoup object with the same DlogGroup definition as party1. 
    //Generate a keyPair using the CramerShoup object.
    KeyPair pair = encryptor.generateKey();
    
    //Publish your public key.
    Publish(pair.getPublic());
    
    //Set private key and party1's public key: 
    encryptor.setKey(party1PublicKey, pair.getPrivate());
    
    //Get the ciphertext and decrypt it to get the plaintext. ...
    ByteArrayPlaintext plaintext = ((ByteArrayPlaintext)encryptor).decrypt(cipher);
    
    //Get the plaintext bytes and use it as needed.
    byte[] text = plaintext.getText();


Damgard Jurik Encryption Scheme
-------------------------------

Damgard Jurik is an asymmetric encryption scheme that is based on the Paillier encryption scheme. This encryption scheme is CPA-secure and Indistinguishable.

Interface
~~~~~~~~~

.. java:type:: public interface DamgardJurikEnc extends AsymAdditiveHomomorphicEnc
   :package: edu.biu.scapi.midLayer.asymmetricCrypto.encryption

   General interface for DamgardJurik encryption scheme. Every concrete implementation of DamgardJurik encryption should implement this interface. 
   By definition, this encryption scheme is CPA-secure and Indistinguishable.

.. java:method:: public AsymmetricCiphertext reRandomize(AsymmetricCiphertext cipher)
   :outertype: DamgardJurikEnc

   This function takes an encryption of some plaintext (let's call it originalPlaintext) and returns a cipher that "looks" different but it is also an encryption of originalPlaintext.

   :param cipher:
   :throws IllegalArgumentException: if the given ciphertext does not match this asymmetric encryption.
   :throws IllegalStateException: if no public key was set.

Scapi Implementation
~~~~~~~~~~~~~~~~~~~~

.. java:type:: public class ScDamgardJurikEnc implements DamgardJurikEnc
   :package: edu.biu.scapi.midLayer.asymmetricCrypto.encryption

   Damgard Jurik is an asymmetric encryption scheme based on the Paillier encryption scheme. This encryption scheme is CPA-secure and Indistinguishable.

.. java:constructor:: public ScDamgardJurikEnc()
   :outertype: ScDamgardJurikEnc

   Default constructor. Uses the default implementations of SecureRandom.

.. java:constructor:: public ScDamgardJurikEnc(SecureRandom rnd)
   :outertype: ScDamgardJurikEnc

   Constructor that lets the user choose the source of randomness.

   :param rnd: source of randomness.

Basic Usage
~~~~~~~~~~~

The code example below is used when the sender and receiver know the specific type of asymmetric encryption object.

Sender code:

.. code-block:: java

    //Create a DamgardJurik encryption object.
    DamgardJurikEnc encryptor = new ScDamgardJurikEnc();
    
    //Generate a keyPair using the DamgardJurik object.
    KeyPair pair = encryptor.generateKey(new DJKeyGenParameterSpec(128, 40));
    
    //Publish your public key.
    Publish(pair.getPublic());
    
    //Set private key and party2's public key: 
    encryptor.setKey(party2PublicKey, pair.getPrivate());
    
    //Get the BigInteger value to encrypt, create a BigIntegerPlaintext with it and encrypt the plaintext.
    ...
    BigIntegerPlainText plaintext = new BigIntegerPlainText(num); 
    AsymmetricCiphertext cipher = encryptor.encrypt(plaintext);
    
    //Send cipher and keys to the receiver.

Receiver code:

.. code-block:: java

    //Create a DamgardJurik object with the same definition as party1. 
    //Generate a keyPair using the DamgardJurik object.
    KeyPair pair = encryptor.generateKey();
    
    //Publish your public key.
    Publish(pair.getPublic());
    
    //Set private key and party1's public key: 
    encryptor.setKey(party1PublicKey, pair.getPrivate());
    
    //Get the ciphertext and decrypt it to get the plaintext. ...
    BigIntegerPlainText plaintext = (BigIntegerPlainText)elGamal.decrypt(cipher);
    
    //Get the plaintext element and use it as needed.
    BigInteger element = plaintext.getX();


RSA Oaep Encryption Scheme
--------------------------

RSA-OAEP is a public-key encryption scheme combining the RSA algorithm with the Optimal Asymmetric Encryption Padding (OAEP) method.

Interface
~~~~~~~~~

.. java:type:: public interface RSAOaepEnc extends AsymmetricEnc, Cca2
   :package: edu.biu.scapi.midLayer.asymmetricCrypto.encryption

   General interface for RSA OAEP encryption scheme. Every concrete implementation of RSA OAEP encryption should implement this interface. 
   By definition, this encryption scheme is CCA-secure and NonMalleable.

Scapi Implementation
~~~~~~~~~~~~~~~~~~~~

.. java:type:: public class BcRSAOaep extends RSAOaepAbs
   :package: edu.biu.scapi.midLayer.asymmetricCrypto.encryption

   RSA-OAEP encryption scheme based on BC library's implementation. By definition, this encryption scheme is CCA-secure and NonMalleable.

.. java:constructor:: public BcRSAOaep()
   :outertype: BcRSAOaep

   Default constructor. Uses default implementation of SecureRandom as source of randomness.

.. java:constructor:: public BcRSAOaep(SecureRandom random)
   :outertype: BcRSAOaep

   Constructor that lets the user choose the source of randomness.

   :param random: source of randomness.

Crypto++ Implementation
~~~~~~~~~~~~~~~~~~~~~~~

.. java:type:: public class CryptoPPRSAOaep extends RSAOaepAbs
   :package: edu.biu.scapi.midLayer.asymmetricCrypto.encryption

   RSA-OAEP encryption scheme based on Crypto++ library's implementation. By definition, this encryption scheme is CCA-secure and NonMalleable.

.. java:constructor:: public CryptoPPRSAOaep()
   :outertype: CryptoPPRSAOaep

   Default constructor. Uses default implementation of SecureRandom as source of randomness.

.. java:constructor:: public CryptoPPRSAOaep(SecureRandom secureRandom)
   :outertype: CryptoPPRSAOaep

   Constructor that lets the user choose the source of randomness.

   :param secureRandom: source of randomness.

OpenSSL Implementation
~~~~~~~~~~~~~~~~~~~~~~

.. java:type:: public class OpenSSLRSAOaep extends RSAOaepAbs
   :package: edu.biu.scapi.midLayer.asymmetricCrypto.encryption

   RSA-OAEP encryption scheme based on OpenSSL library's implementation. By definition, this encryption scheme is CCA-secure and NonMalleable.

.. java:constructor:: public OpenSSLRSAOaep()
   :outertype: OpenSSLRSAOaep

   Default constructor. Uses default implementation of SecureRandom as source of randomness.

.. java:constructor:: public OpenSSLRSAOaep(SecureRandom secureRandom)
   :outertype: OpenSSLRSAOaep

   Constructor that lets the user choose the source of randomness.

   :param secureRandom: source of randomness.

Basic Usage
~~~~~~~~~~~

Sender code:

.. code-block:: java

    //Create an RSA encryption object.
    RSAOaepEnc encryptor = new CryptoPPRSAOaep();
    
    //Generate a keyPair using the RSAOaep object.
    KeyPair pair = encryptor.generateKey(new RSAKeyGenParameterSpec(1024, null));
    
    //Publish your public key.
    Publish(pair.getPublic());
    
    //Set private key and party2's public key: 
    encryptor.setKey(party2PublicKey, pair.getPrivate());
    
    //Get a byte[] message to encrypt. Check if the length of the given msg is valid.
    if (encryptor.hasMaxByteArrayLengthForPlaintext()){
        if (msg.length>encryptor.getMaxLengthOfByteArrayForPlaintext()) {
    	    throw new IllegalArgumentException(“message too long”);
        }
    }
    
    //Generate a plaintext suitable to this RSAOaep object.
    Plaintext plaintext = encryptor.generatePlaintext(msg);
    
    //Encrypt the plaintext
    AsymmetricCiphertext cipher = encrypor.encrypt(plaintext);
    
    //Send cipher and keys to the receiver.

Receiver code:

.. code-block:: java

    //Create the same RSAOaep object with the same definition as the sender’s object.
    //Generate a keyPair using the RSAOaep object.
    KeyPair pair = encryptor.generateKey();
    
    //Publish your public key.
    Publish(pair.getPublic());
    
    //Set private key and party1's public key: 
    encryptor.setKey(party1PublicKey, pair.getPrivate());
    
    //Get the ciphertext and decrypt it to get the plaintext. 
    ...
    ByteArrayPlaintext plaintext = ((ByteArrayPlaintext)encryptor).decrypt(cipher);
    
    //Get the plaintext bytes and use it as needed.
    byte[] text = plaintext.getText();
    ...
