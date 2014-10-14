package in.ajsd.jwt;

import com.google.common.base.Joiner;
import com.google.common.base.Splitter;
import com.google.gson.FieldNamingPolicy;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.LongSerializationPolicy;

import org.apache.commons.codec.binary.Base64;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class Util {

  static final Gson GSON = new GsonBuilder()
      .setLongSerializationPolicy(LongSerializationPolicy.DEFAULT)
      .disableHtmlEscaping()
      .setFieldNamingPolicy(FieldNamingPolicy.LOWER_CASE_WITH_UNDERSCORES)
      .create();

  static final String JWT_TOKEN_SEPARATOR = ".";
  static final Splitter JWT_TOKEN_SPLITTER = Splitter.on(JWT_TOKEN_SEPARATOR);
  static final Joiner JWT_TOKEN_JOINER = Joiner.on(JWT_TOKEN_SEPARATOR);

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

  static List<String> split(String token) {
    return JWT_TOKEN_SPLITTER.splitToList(token);
  }

  static String join(String... parts) {
    return JWT_TOKEN_JOINER.join(parts);
  }

  static JwtData createJwtData(String headerBase64, String claimsBase64) {
    String headerJson = new String(base64Decode(headerBase64));
    String claimsJson = new String(base64Decode(claimsBase64));
    JwtData.Header header = GSON.fromJson(headerJson, JwtData.Header.class);
    JwtData.Claims claims = GSON.fromJson(claimsJson, JwtData.Claims.class);
    return JwtData.of(header, claims);
  }

  static String toJson(JwtData jwt) {
    return Util.join(
        Util.base64Encode(Util.GSON.toJson(jwt.getHeader())),
        Util.base64Encode(Util.GSON.toJson(jwt.getClaims())));
  }

  static void verifyHmac(byte[] secret, String algorithm, String unsigned, String signature)
      throws JwtException {
    byte[] toVerify = {};
    try {
      SecretKeySpec key = new SecretKeySpec(secret, algorithm);
      Mac hmac = Mac.getInstance(algorithm);
      hmac.init(key);
      toVerify = hmac.doFinal(unsigned.getBytes());
    } catch (NoSuchAlgorithmException | InvalidKeyException e) {
      throw new JwtException(e);
    }
    if (!Arrays.equals(toVerify, Util.base64Decode(signature))) {
      throw new JwtException("Signatures do not match");
    }
  }
}
