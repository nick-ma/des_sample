import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Hex;
import org.junit.Test;

  @Test
  public void encrypt_3des_ecb() throws Exception {
    byte[] key = "0123456789abcd0123456789".getBytes();   
    byte[] plainText = "1234567812345678".getBytes();
    
//    KeySpec myKeySpec = new DESedeKeySpec(key);
//    SecretKeyFactory mySecretKeyFactory = SecretKeyFactory.getInstance("DESede");
//    SecretKey secretKey = mySecretKeyFactory.generateSecret(myKeySpec);
    SecretKey secretKey = new SecretKeySpec(key, "DESede");
    //encrypt
    Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
    cipher.init(Cipher.ENCRYPT_MODE, secretKey);
    byte[] encryptedData = cipher.doFinal(plainText);
    System.out.println("encrypt_3des_ecb: " + Hex.encodeHexString(encryptedData));
    
    //decrypt
    cipher.init(Cipher.DECRYPT_MODE, secretKey);
    byte[] decryptPlainText = cipher.doFinal(encryptedData);
    org.junit.Assert.assertArrayEquals(decryptPlainText, plainText);    
  }
  
  @Test
  // 3DES加密
  public void encrypt_3des_cbc() throws Exception {
    byte[] key = "0123456789abcd0123456789".getBytes();   
    byte[] plainText = "1234567812345678".getBytes();
    IvParameterSpec iv = new IvParameterSpec("12345678".getBytes());
    
    SecretKey secretKey = new SecretKeySpec(key, "DESede");
    //encrypt
    Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
    cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
    byte[] encryptedData = cipher.doFinal(plainText);
    System.out.println("encrypt_3des_cbc: " + Hex.encodeHexString(encryptedData));
    
    //decrypt
    cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
    byte[] decryptPlainText = cipher.doFinal(encryptedData);
    org.junit.Assert.assertArrayEquals(decryptPlainText, plainText);      
  } 

  @Test
  public void encrypt_des_ecb() throws Exception {
    byte[] key = "01234567".getBytes();   
    byte[] plainText = "1234567812345678".getBytes();
    
    SecretKey secretKey = new SecretKeySpec(key, "DES");
    //encrypt
    Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
    cipher.init(Cipher.ENCRYPT_MODE, secretKey);    
    byte[] encryptedData = cipher.doFinal(plainText);
    System.out.println("encrypt_des_ecb: " + Hex.encodeHexString(encryptedData));
    
    //decrypt
    cipher.init(Cipher.DECRYPT_MODE, secretKey);
    byte[] decryptPlainText = cipher.doFinal(encryptedData);
    org.junit.Assert.assertArrayEquals(decryptPlainText, plainText);
  }
  
  @Test
  public void encrypt_des_cbc() throws Exception {
    byte[] key = "01234567".getBytes();   
    byte[] plainText = "1234567812345678".getBytes();
    IvParameterSpec iv = new IvParameterSpec("12345678".getBytes()); 
    
    SecretKey secretKey = new SecretKeySpec(key, "DES");
    //encrypt
    Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
    cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);    
    byte[] encryptedData = cipher.doFinal(plainText);
    System.out.println("encrypt_des_cbc: " + Hex.encodeHexString(encryptedData));
    
    //decrypt
    cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
    byte[] decryptPlainText = cipher.doFinal(encryptedData);
    org.junit.Assert.assertArrayEquals(decryptPlainText, plainText);
  } 