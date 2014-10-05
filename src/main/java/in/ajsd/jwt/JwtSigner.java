package in.ajsd.jwt;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** A signer for JWT tokens. */
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

  /** Signs JWT data ([header,] claims) and returns a JWT token. */
  public String sign(JwtData jwt) throws JwtException {
    try {
      Mac hmac = Mac.getInstance(algorithm.getName());
      hmac.init(key);
      String unsigned = Util.join(
          Util.base64Encode(Util.GSON.toJson(jwt.getHeader())),
          Util.base64Encode(Util.GSON.toJson(jwt.getClaims())));

      String signature = Util.base64Encode(hmac.doFinal(unsigned.getBytes()));
      return Util.join(unsigned, signature);
    } catch (NoSuchAlgorithmException | InvalidKeyException e) {
      throw new JwtException(e);
    }
  }

  public static String createToken(byte[] secret, JwtData jwt) throws JwtException {
    JwtSigner signer = new JwtSigner(secret, Algorithm.fromJwt(jwt.getAlgorithm()));
    return signer.sign(jwt);
  }

  public static String createToken(String urlSafeBase64Secret, JwtData jwt)
      throws JwtException {
    return createToken(Util.base64Decode(urlSafeBase64Secret), jwt);
  }
}
