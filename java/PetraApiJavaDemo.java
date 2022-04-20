import sinsiway.*;

public class PetraApiJavaDemo {

  public static void main(String[] args) {
    cipherDemo();
  }

  private static void cipherDemo() {
    try {
      sinsiway.PcaSession session = sinsiway.PcaSessionPool.getSession();

      String encryptString = new String();
      String decryptString = new String();

      int keyId = 10;
      String keyName = new String("ARIA_256_b64");

      // case 01 : use key id
      String plainString = new String("Believe in yourself.");
      encryptString = session.encrypt(keyId, plainString);
      decryptString = session.decrypt(keyId, encryptString);

      System.out.println(
        "\n|| CASE 01 : Use Key Key Id" +
        "\n|| ex) String sinsiway.PcaSession.decrypt(int eci, String src) throws PcaException\n||"
      );
      System.out.println("|| [" + plainString + "]\n||");
      System.out.println("|| Encrypt String : " + encryptString);
      System.out.println("|| Decrypt String : " + decryptString);

      // case 02 : use key name
      plainString = new String("Follow your heart.");
      encryptString = session.encrypt(keyName, plainString);
      decryptString = session.decrypt(keyName, encryptString);

      System.out.println(
        "\n|| CASE 02 : Use Key Key Name" +
        "\n|| String sinsiway.PcaSession.encrypt(String ecn, String src) throws PcaException\n||"
      );
      System.out.println("|| [" + plainString + "]\n||");
      System.out.println("|| Encrypt String : " + encryptString);
      System.out.println("|| Decrypt String : " + decryptString);
      //   System.out.println("decrypt stirng= " + dec_str);
      //   session.logCurrRequest(1, "pgm01 ", "user01");

    } catch (PcaException e) {
      System.out.println(
        "error_code = " + e.getErrCode() + "  error_message = " + e.getMessage()
      );
      return;
    }
  }
}
