package ir.fidar.pam.session;

import java.util.Map;

public interface OcrHttpClient {
   String sendExtractionRequest(String var1);

   String sendExtractionRequest(String var1, Integer var2);

   String sendExtractionRequest(String var1, Integer var2, OcrHttpClient.Dataset var3);

   String sendExtractionRequest(String var1, Integer var2, OcrHttpClient.Dataset var3, int var4);

   String sendExtractionRequest(String var1, Integer var2, OcrHttpClient.Dataset var3, int var4, Map<String, String> var5);

   String sendExtractionRequest(String var1, Integer var2, OcrHttpClient.Dataset var3, int var4, Map<String, String> var5, boolean var6);

   String sendExtractionRequest(byte[] var1);

   String sendExtractionRequest(byte[] var1, Integer var2);

   String sendExtractionRequest(byte[] var1, Integer var2, OcrHttpClient.Dataset var3);

   String sendExtractionRequest(byte[] var1, Integer var2, OcrHttpClient.Dataset var3, int var4);

   String sendExtractionRequest(byte[] var1, Integer var2, OcrHttpClient.Dataset var3, int var4, Map<String, String> var5);

   String sendExtractionRequest(byte[] var1, Integer var2, OcrHttpClient.Dataset var3, int var4, Map<String, String> var5, boolean var6);

   public static enum Dataset {
      BEST,
      FAST,
      LEGACY;
   }
}
