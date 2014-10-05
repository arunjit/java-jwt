package in.ajsd.jwt;

import com.google.gson.FieldNamingPolicy;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.LongSerializationPolicy;

import org.apache.commons.codec.binary.Base64;

class Util {

  static final Gson GSON = new GsonBuilder()
      .setLongSerializationPolicy(LongSerializationPolicy.DEFAULT)
      .disableHtmlEscaping()
      .setFieldNamingPolicy(FieldNamingPolicy.LOWER_CASE_WITH_UNDERSCORES)
      .create();

  static String base64Encode(byte[] input) {
    return Base64.encodeBase64URLSafeString(input);
  }

  static String base64Encode(String input) {
    return base64Encode(input.getBytes());
  }

  static byte[] base64Decode(String input) {
    return Base64.decodeBase64(input);
  }

//  static byte[] base64Decode(byte[] input) {
//    return Base64.decodeBase64(input);
//  }
}
