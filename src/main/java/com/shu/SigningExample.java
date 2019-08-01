package example;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.FileNotFoundException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.Signature;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.SignedObject;
import java.security.KeyPairGenerator;
import java.security.SignatureException;
import java.security.InvalidKeyException;
import java.security.NoSuchProviderException;
import java.security.NoSuchAlgorithmException;

public class SigningExample
{
	private PrivateKey privateKey = null;
	private PublicKey  publicKey  = null;
	
 	private final String ALGORITM_DSA = "DSA"; // Digital Signature Algorithm
	private final String MESSAGE      = "Пусть всегда будет солнце";
	private final String FILE_private = "private.key";
	private final String FILE_public  = "public.key" ;
	
	public SigningExample()
	{
	    try {
	    	createKeys();
	    	saveKey(FILE_private, privateKey);
	    	saveKey(FILE_public , publicKey );
	    	
	    	privateKey = (PrivateKey) readKey(FILE_private);
	    	publicKey  = (PublicKey ) readKey(FILE_public );
	    	
		    SignedObject signedObject = createSignedObject(MESSAGE, privateKey);
			     
		    // Проверка подписанного объекта
		    boolean verified = verifySignedObject(signedObject, publicKey);
		    System.out.println("Проверка подписи объекта : " + verified);
			     
		    // Извлечение подписанного объекта
		    String unsignedObject = (String) signedObject.getObject();

		    System.out.println("Исходный текст объекта : " + unsignedObject);
		     
	    } catch (ClassNotFoundException e) {
	    } catch (IOException e) {
	    	System.err.println("Exception thrown during test: " + e.toString());
	    } catch (InvalidKeyException e) {
			System.err.println(e.getMessage());
		} catch (SignatureException e) {
			System.err.println(e.getMessage());
		} catch (NoSuchAlgorithmException e) {
			System.err.println(e.getMessage());
		} catch (NoSuchProviderException e) {
			System.err.println(e.getMessage());
		}
	}
	private SignedObject createSignedObject(final String message, PrivateKey key) throws InvalidKeyException, 
	                               SignatureException, IOException, NoSuchAlgorithmException
	{
		Signature signature = Signature.getInstance(key.getAlgorithm());
		return new SignedObject(message, key, signature);
	}
	private boolean verifySignedObject(final SignedObject signedObject, PublicKey key)
            throws InvalidKeyException, SignatureException, NoSuchAlgorithmException
    {
		// Verify the signed object
		Signature signature = Signature.getInstance(key.getAlgorithm());
		return signedObject.verify(key, signature);
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
	
	private void saveKey(final String filePath, final Object key) 
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
	
	private Object readKey(final String filePath)
			               throws FileNotFoundException, IOException, ClassNotFoundException
	{
		FileInputStream fis = new FileInputStream(filePath);
		ObjectInputStream ois = new ObjectInputStream(fis);
		Object object = ois.readObject();
		return object;
	}
	public static void main(String[] args)
	{
		new SigningExample();
		System.exit(0);
	}
}
