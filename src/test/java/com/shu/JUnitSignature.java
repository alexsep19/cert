package test;

import java.io.File;
import java.io.IOException;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.BufferedInputStream;
import java.io.FileNotFoundException;

import java.security.KeyPair;
import java.security.PublicKey;
import java.security.Signature;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.KeyPairGenerator;
import java.security.SignatureException;
import java.security.InvalidKeyException;
import java.security.NoSuchProviderException;
import java.security.NoSuchAlgorithmException;

import org.junit.Test;
import org.junit.AfterClass;

import static org.junit.Assert.*;

public class JUnitSignature
{
	private static final String MESSAGE = "Пусть всегда будет солнце";	
	private static final String FILE_sign = "data.sign";

	@AfterClass
	public static void tearDownAfterClass() throws Exception {
    	// Удаление файла
		new File(FILE_sign).delete();
		
		File file = new File(FILE_sign);
		assertTrue("Файл не удален", !file.exists());
	}
	@Test
	public void testSignature()
	{
	    try {
	    	/*
	    	 * 1-ый этап. Генерирование пары ключей
	    	 */
		    // Generate a 1024-bit Digital Signature Algorithm (DSA) key pair
		    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA", "SUN");
		    SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
		    keyPairGenerator.initialize(1024, random);
		    KeyPair    keyPair    = keyPairGenerator.genKeyPair();
		    PrivateKey privateKey = keyPair.getPrivate();
		    PublicKey  publicKey  = keyPair.getPublic();

		    /*
		     * 2-ой этап. Формирование цифровой подписи сообщения
		     */
		    // Создание подписи
		    Signature signature = Signature.getInstance("SHA1withDSA", "SUN");
		    // Инициализация подписи закрытым ключом
		    signature.initSign(privateKey);

		    // Формирование цифровой подпись сообщения с закрытым ключом
		    signature.update(MESSAGE.getBytes());
		    // Байтовый массив цифровой подписи
		    byte[] realSignature = signature.sign();

		    // Сохранение цифровой подписи сообщения в файл
		    FileOutputStream fos = new FileOutputStream(FILE_sign);
		    fos.write(realSignature);
		    fos.close();
		    /*
		     * 3-ий этап. Проверка цифровой подписи сообщения
		     */
			// Инициализация цифровой подписи открытым ключом
			signature.initVerify(publicKey);
			// Формирование цифровой подпись сообщения с открытым ключом
			signature.update(MESSAGE.getBytes());
			
			// Открытие и чтение цифровой подписи сообщения
			FileInputStream fis = new FileInputStream(FILE_sign);
			BufferedInputStream bis = new BufferedInputStream(fis);
			byte[] bytesSignature = new byte[bis.available()];
			bis.read(bytesSignature);
		    fis.close();
			
			// Проверка цифровой подписи
			boolean verified = signature.verify(bytesSignature);
			assertTrue("Проверка цифровой подписи", verified);
		    
	    } catch (SignatureException e) {
	    } catch (InvalidKeyException e) {
	    } catch (NoSuchAlgorithmException e) {
		} catch (NoSuchProviderException e) {
	    } catch (FileNotFoundException e) {
	    } catch (IOException e) {
	    	fail("Exception thrown during test: " + e.toString());
	    }
	}
}
