package in.ajsd.jwt;

import org.joda.time.DateTime;

import java.util.List;

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
    JwtData jwt = Util.createJwtData(parts.get(0), parts.get(1));
    Util.verifyHmac(secret, Algorithm.fromJwt(jwt.getAlgorithm()).getName(),
        Util.join(parts.get(0), parts.get(1)), parts.get(2));

    long now = DateTime.now().getMillis();
    verifyExpires(jwt.getExpires(), now);
    verifyNotBefore(jwt.getNotBefore(), now);
    // TODO: Add verification for aud,iat,jti

    return jwt;
  }

  static void verifyExpires(Long expires, long now) throws JwtException {
    if (expires != null && now < expires) {  // TODO: threshold
      throw new JwtException("Token has expired");
    }
  }

  static void verifyNotBefore(Long notBefore, long now) throws JwtException {
    if (notBefore != null && now > notBefore) {
      throw new JwtException("Token isn't valid yet");
    }
  }
}
