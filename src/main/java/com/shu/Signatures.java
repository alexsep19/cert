package com.shu;

import java.io.*;
import java.security.*;

public class Signatures {

    static public void CriptoSign(String message, String privateKeyFile, String publicKeyFile, String signFile) throws Exception {
        Keys keys = new Keys(privateKeyFile, publicKeyFile);
        SignedObject signedObject = createSignedObject(message, keys.getPrivateKey());
        Keys.saveObjectToFile(signFile, signedObject);
    }

    static public String CriptoVerify(String publicKeyFile, String signFile) throws IOException, ClassNotFoundException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        PublicKey publicKey = (PublicKey) Keys.readObjectFromFile(publicKeyFile);
        SignedObject signedObject = (SignedObject) Keys.readObjectFromFile(signFile);
        // Проверка подписанного объекта
        if (!verifySignedObject(signedObject, publicKey)){
            throw new SignatureException("Sign not verified");
        }
        // Извлечение подписанного объекта
        return (String) signedObject.getObject();
    }

    static private boolean verifySignedObject(final SignedObject obj, PublicKey key)
            throws InvalidKeyException, SignatureException,
            NoSuchAlgorithmException
    {
        // Verify the signed object
        Signature signature = Signature.getInstance(key.getAlgorithm());
        return obj.verify(key, signature);
    }

    static private SignedObject createSignedObject(final String msg, PrivateKey key)
            throws InvalidKeyException, SignatureException,
            IOException, NoSuchAlgorithmException
    {
        Signature signature = Signature.getInstance(key.getAlgorithm());
        return new SignedObject(msg, key, signature);
    }

    /**
     * Создать файл подписи
     * @param message сообщение для подписи
     * @param
     * @param signFile путь и имя файла с подписью
     */
    static public void DigestSign(String message, String privateKeyFile, String publicKeyFile, String signFile)
            throws Exception {
        Keys keys = new Keys(privateKeyFile, publicKeyFile);
    // Создание подписи
        Signature signature = Signature.getInstance("SHA1withDSA", "SUN");
    // Инициализация подписи закрытым ключом
        signature.initSign(keys.getPrivateKey());

    // Формирование цифровой подпись сообщения с закрытым ключом
        signature.update(message.getBytes());
    // Байтовый массив цифровой подписи
        byte[] realSignature = signature.sign();

    // Сохранение цифровой подписи сообщения в файл
        try(FileOutputStream fos = new FileOutputStream(signFile)){
        fos.write(realSignature);
        }
    }

    /**
     *
     * @param message подписанное сообщение
     * @param
     * @param signFile путь и имя файла с подписью
     * @return
     */
    static public boolean DigestVerify(String message, String publicKeyFile, String signFile)
            throws Exception {
    // Создание подписи
        Signature signature = Signature.getInstance("SHA1withDSA", "SUN");
    // Инициализация цифровой подписи открытым ключом
        signature.initVerify((PublicKey) Keys.readObjectFromFile(publicKeyFile));
    // Формирование цифровой подпись сообщения с открытым ключом
        signature.update(message.getBytes());

    // Открытие и чтение цифровой подписи сообщения
        byte[] bytesSignature = null;
        try(FileInputStream fis = new FileInputStream(signFile);
            BufferedInputStream bis = new BufferedInputStream(fis)) {
            bytesSignature = new byte[bis.available()];
            bis.read(bytesSignature);
        }

    // Проверка цифровой подписи
        return bytesSignature != null && signature.verify(bytesSignature);
    }
}
