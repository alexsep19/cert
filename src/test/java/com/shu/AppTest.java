package com.shu;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.io.File;

/**
 * Unit test for simple App.
 */
public class AppTest 
{
    String privateKeyFile = "private.key";
    String publicKeyFile = "public.key";
    String signFile = "data.sign";
    String message = "Формирование цифровой подпись сообщения с закрытым ключом";

    @Test
    public void DigestSignTest() throws Exception {
        try{
            Signatures.DigestSign( message, privateKeyFile, publicKeyFile, signFile);
            assertTrue( Signatures.DigestVerify( message, publicKeyFile, signFile));
        }finally {
            delFile("private.key");
            delFile("public.key");
            delFile("data.sign");
        }
    }

    @Test
    public void CriptoSignTest() throws Exception {
        try{
            Signatures.CriptoSign( message, privateKeyFile, publicKeyFile, signFile);
            assertEquals("Должны совпадать", Signatures.CriptoVerify( publicKeyFile, signFile), message);
        }finally {
            delFile("private.key");
            delFile("public.key");
            delFile("data.sign");
        }
    }

    private void delFile(String filePath){
        new File(filePath).delete();
        File file = new File(filePath);
        assertTrue("Файл не удален", !file.exists());
    }
}
