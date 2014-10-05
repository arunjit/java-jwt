package in.ajsd.jwt;

import org.joda.time.DateTime;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** A verifier to verify JWT tokens. */
public class JwtVerifier {

  private final byte[] secret;

  public JwtVerifier(byte[] secret) {
    this.secret = secret;
  }

  public JwtVerifier(String urlSafeBase64Secret) {
    this(Util.base64Decode(urlSafeBase64Secret));
  }

  public JwtData verify(String token) throws JwtException {
    List<String> parts = Util.split(token);
    if (parts.size() != 3) {
      throw new JwtException("Malformed token");
    }
    JwtData jwt = createJwtData(parts.get(0), parts.get(1));
    verifySignature(Util.join(parts.get(0), parts.get(1)), parts.get(2),
        Algorithm.fromJwt(jwt.getAlgorithm()));

    long now = DateTime.now().getMillis();
    verifyExpires(jwt.getExpires(), now);
    verifyNotBefore(jwt.getNotBefore(), now);
    // TODO: Add verification for aud,iat,jti

    return jwt;
  }

  public void verifySignature(String unsigned, String signature, Algorithm algorithm)
      throws JwtException {
    byte[] toVerify = {};
    try {
      SecretKeySpec key = new SecretKeySpec(secret, algorithm.getName());
      Mac hmac = Mac.getInstance(algorithm.getName());
      hmac.init(key);
      toVerify = hmac.doFinal(unsigned.getBytes());
    } catch (NoSuchAlgorithmException | InvalidKeyException e) {
      throw new JwtException(e);
    }
    if (!Arrays.equals(toVerify, Util.base64Decode(signature))) {
      throw new JwtException("Signatures do not match");
    }
  }

  public void verifyExpires(Long expires, long now) throws JwtException {
    if (expires != null && now < expires) {  // TODO: threshold
      throw new JwtException("Token has expired");
    }
  }

  public void verifyNotBefore(Long notBefore, long now) throws JwtException {
    if (notBefore != null && now > notBefore) {
      throw new JwtException("Token isn't valid yet");
    }
  }

  public static JwtData verifyToken(byte[] secret, String token) throws JwtException {
    return new JwtVerifier(secret).verify(token);
  }

  public static JwtData verifyToken(String urlSafeBase64Secret, String token)
      throws JwtException {
    return new JwtVerifier(urlSafeBase64Secret).verify(token);
  }

  private static JwtData createJwtData(String headerBase64, String claimsBase64) {
    String headerJson = new String(Util.base64Decode(headerBase64));
    String claimsJson = new String(Util.base64Decode(claimsBase64));
    JwtData.Header header = Util.GSON.fromJson(headerJson, JwtData.Header.class);
    JwtData.Claims claims = Util.GSON.fromJson(claimsJson, JwtData.Claims.class);
    return JwtData.of(header, claims);
  }
}
