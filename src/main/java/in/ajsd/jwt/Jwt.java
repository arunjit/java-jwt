package in.ajsd.jwt;

import java.util.List;

public class Jwt {

  /** Parses a JWT token and extracts the JWT payload without verification. */
  public static JwtData parse(String token) throws JwtException {
    List<String> parts = Util.split(token);
    if (parts.size() != 3) {
      throw new JwtException("Malformed token");
    }
    return Util.createJwtData(parts.get(0), parts.get(1));
  }

  /** Signs some JWT payload using a secret. */
  public static String sign(byte[] secret, JwtData jwt) throws JwtException {
    JwtSigner signer = new JwtSigner(secret, Algorithm.fromJwt(jwt.getAlgorithm()));
    return signer.sign(jwt);
  }

  /** Signs some JWT payload using a secret. */
  public static String sign(String urlSafeBase64Secret, JwtData jwt)
      throws JwtException {
    return sign(Util.base64Decode(urlSafeBase64Secret), jwt);
  }

  /** Verifies a JWT token using a secret. */
  public static JwtData verify(byte[] secret, String token) throws JwtException {
    return new JwtVerifier(secret).verify(token);
  }

  /** Verifies a JWT token using a secret. */
  public static JwtData verify(String urlSafeBase64Secret, String token)
      throws JwtException {
    return new JwtVerifier(urlSafeBase64Secret).verify(token);
  }

  private Jwt() {}
}
