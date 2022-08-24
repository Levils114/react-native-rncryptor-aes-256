
package com.rncryptorbase64;

import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.Callback;
import com.facebook.react.bridge.Promise;

import android.util.Base64;
import java.math.BigInteger;
import java.io.*;

import org.cryptonode.jncryptor.*;

public class RNRncryptorModule extends ReactContextBaseJavaModule {

  private final ReactApplicationContext reactContext;

  public RNRncryptorModule(ReactApplicationContext reactContext) {
    super(reactContext);
    this.reactContext = reactContext;
  }

  @Override
  public String getName() {
    return "RNRncryptor";
  }

  @ReactMethod
  public void encrypt(String text, String password, Promise promise) {
    JNCryptor cryptor = new AES256JNCryptor();
    byte[] plaintext = text.getBytes();

    try {
      byte[] ciphertext = cryptor.encryptData(plaintext, password.toCharArray());
      String base64 = Base64.encodeToString(ciphertext, Base64.DEFAULT);
      promise.resolve(base64);
    } catch (CryptorException e) {
      e.printStackTrace();
      promise.reject(e);
    }
  }

  @ReactMethod
  public void decrypt(String encrypted, String password, Promise promise) {
    JNCryptor cryptor = new AES256JNCryptor();
    byte[] data = Base64.decode(encrypted, Base64.DEFAULT);

    try {
      byte[] text = cryptor.decryptData(data, password.toCharArray());
      promise.resolve(Base64.encodeToString(text, Base64.DEFAULT));
    } catch (CryptorException e) {
      e.printStackTrace();
      promise.reject(e);
    }
  }

  @ReactMethod
  public void decryptStream(String password, String cryptedFilePath, String destPath, Promise promise) {
    try{
      FileInputStream fileInputStream = new FileInputStream(cryptedFilePath);
      BufferedInputStream fileBufferedInputStream = new BufferedInputStream(fileInputStream);
      InputStream AESinStream = new AES256JNCryptorInputStream(fileBufferedInputStream, password.toCharArray());
      File finalFile = new File(destPath);
      FileOutputStream fileOutputStream = new FileOutputStream(finalFile);
      BufferedOutputStream fileBufferedOutputStream = new BufferedOutputStream(fileOutputStream);

      int total = 0;

      try {    
        byte[] buffer = new byte[8192];
        
        int i;
        while ((i=AESinStream.read(buffer))!=-1) {
          total += i;
          fileBufferedOutputStream.write(buffer, 0, i);
        }
      } catch (Exception e) {
        promise.reject(e);
      } finally {
        fileBufferedOutputStream.close();
        promise.resolve(true);
      }
    } catch(Exception e){
      e.printStackTrace();
      promise.reject(e);
    }
  }
}