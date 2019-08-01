package com.shu;

import java.io.*;
import java.security.*;

public class Keys {
    private PrivateKey privateKey = null;
    private PublicKey publicKey  = null;
    private final String ALGORITM_DSA = "DSA"; // Digital Signature Algorithm

    public Keys() throws Exception{
        createKeys();
    }
    /**
     * Процедура генерирования закрытого и открытого ключей
     */
    private void createKeys() throws NoSuchAlgorithmException, NoSuchProviderException
    {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITM_DSA, "SUN");
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
        keyPairGenerator.initialize(1024, random);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        privateKey = keyPair.getPrivate();
        publicKey  = keyPair.getPublic();
    }

    public void saveKey(final String filePath, final Object key)
            throws FileNotFoundException, IOException
    {
        if (key != null){
            FileOutputStream fos = new FileOutputStream(filePath);
            ObjectOutputStream oos = new ObjectOutputStream(fos);
            oos.writeObject(key);
            oos.close();
            fos.close();
        }
    }

    public Object readKey(final String filePath)
            throws FileNotFoundException, IOException, ClassNotFoundException
    {
        FileInputStream fis = new FileInputStream(filePath);
        ObjectInputStream ois = new ObjectInputStream(fis);
        Object object = ois.readObject();
        return object;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }
}
