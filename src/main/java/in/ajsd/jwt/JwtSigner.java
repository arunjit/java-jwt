package in.ajsd.jwt;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class JwtSigner {

  private final SecretKeySpec key;
  private final Algorithm algorithm;

  public JwtSigner(String urlSafeBase64Secret, Algorithm algorithm) {
    this(Util.base64Decode(urlSafeBase64Secret), algorithm);
  }

  public JwtSigner(byte[] secret, Algorithm algorithm) {
    this.algorithm = algorithm;
    this.key = new SecretKeySpec(secret, algorithm.getName());
  }

  public String sign(JwtData jwt) throws JwtException {
    try {
      Mac hmac = Mac.getInstance(algorithm.getName());
      hmac.init(key);
      String header = Util.base64Encode(Util.GSON.toJson(jwt.getHeader()));
      String payload = Util.base64Encode(Util.GSON.toJson(jwt.getClaims()));
      byte[] sig = hmac.doFinal(new StringBuilder(header)
          .append(".")
          .append(payload)
          .toString().getBytes());
      String signature = Util.base64Encode(sig);
      return new StringBuilder(header)
          .append(".")
          .append(payload)
          .append(".")
          .append(signature).toString();
    } catch (NoSuchAlgorithmException | InvalidKeyException e) {
      throw new JwtException(e);
    }
  }
}
