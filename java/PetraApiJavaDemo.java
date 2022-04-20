import java.util.*;
import sinsiway.*;

public class PetraApiJavaDemo {

  public static void main(String[] args) {
    try {
      sinsiway.PcaSession session = sinsiway.PcaSessionPool.getSession();

      String plainString = new String("Sinsiway Petra Cipher Java Demo.");
      String encryptString = new String();
      String decryptString = new String();

      int keyId = 10;
      String keyName = new String("ARIA_256_b64");
      int rtn = 0;

      encryptString = session.encrypt(keyId, plainString);
      System.out.println("Encrypt String = " + encryptString);
      //   String dec_str = session.decrypt(key_name, enc_str);
      //   System.out.println("decrypt stirng= " + dec_str);
      //   session.logCurrRequest(1, "pgm01 ", "user01");

    } catch (PcaException e) {
      System.out.println(
        "error_code = " + e.getErrCode() + "  error_message = " + e.getMessage()
      );
      return;
    } //try ~ catch end
  } //main end
} //PcaTest end
