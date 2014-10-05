package in.ajsd.jwt;

import com.google.common.base.Strings;

import java.util.ArrayList;
import java.util.List;

public class JwtData {

  private static class Header {
    // "typ" Type
    private String typ = "JWT";

    // "alg" Algorithm
    private String alg = Algorithm.HS256.getJwtName();
  }

  private static class Claims {
    // 4.1.1.  "iss" (Issuer) Claim
    // The iss (issuer) claim identifies the principal that issued the JWT.
    // The processing of this claim is generally application specific. The iss
    // value is a case-sensitive string containing a StringOrURI value.
    // Use of this claim is OPTIONAL.
    private String iss = null;

    // 4.1.2.  "sub" (Subject) Claim
    // The sub (subject) claim identifies the principal that is the subject of
    // the JWT. The Claims in a JWT are normally statements about the subject.
    // The subject value MAY be scoped to be locally unique in the context of the
    // issuer or MAY be globally unique. The processing of this claim is
    // generally application specific. The sub value is a case-sensitive string
    // containing a StringOrURI value.
    // Use of this claim is OPTIONAL.
    private String sub = null;

    // 4.1.3.  "aud" (Audience) Claim
    // The aud (audience) claim identifies the recipients that the JWT is
    // intended for. Each principal intended to process the JWT MUST identify
    // itself with a value in the audience claim. If the principal processing
    // the claim does not identify itself with a value in the aud claim when
    // this claim is present, then the JWT MUST be rejected. In the general case,
    // the aud value is an array of case-sensitive strings, each containing a
    // StringOrURI value. In the special case when the JWT has one audience,
    // the aud value MAY be a single case-sensitive string containing a
    // StringOrURI value. The interpretation of audience values is generally
    // application specific.
    // Use of this claim is OPTIONAL.
    private List<String> aud = null;
    // TODO(arunjit): "aud" can be a list or string. Use:
    // Object aud = null;
    // public String getAudience() {...}
    // public List<String> getAudienceAsList() {...}
    // public Builder setAudience(String value) {...}  // converts to String
    // public Builder addAudience(String value) {...}  // converts to List<String>

    // 4.1.4.  "exp" (Expiration Time) Claim
    // The exp (expiration time) claim identifies the expiration time on or after
    // which the JWT MUST NOT be accepted for processing. The processing of the
    // exp claim requires that the current date/time MUST be before the
    // expiration date/time listed in the exp claim. Implementers MAY provide for
    // some small leeway, usually no more than a few minutes, to account for
    // clock skew. Its value MUST be a number containing a NumericDate value.
    // Use of this claim is OPTIONAL.
    private Long exp = null;

    // 4.1.5.  "nbf" (Not Before) Claim
    // The nbf (not before) claim identifies the time before which the JWT MUST
    // NOT be accepted for processing. The processing of the nbf claim requires
    // that the current date/time MUST be after or equal to the not-before
    // date/time listed in the nbf claim. Implementers MAY provide for some small
    // leeway, usually no more than a few minutes, to account for clock skew.
    // Its value MUST be a number containing a NumericDate value.
    // Use of this claim is OPTIONAL.
    private Long nbf = null;

    // 4.1.6.  "iat" (Issued At) Claim
    // The iat (issued at) claim identifies the time at which the JWT was issued.
    // This claim can be used to determine the age of the JWT. Its value MUST be
    // a number containing a NumericDate value.
    // Use of this claim is OPTIONAL.
    private Long iat = null;

    // 4.1.7.  "jti" (JWT ID) Claim
    // The jti (JWT ID) claim provides a unique identifier for the JWT. The
    // identifier value MUST be assigned in a manner that ensures that there is
    // a negligible probability that the same value will be accidentally assigned
    // to a different data object. The jti claim can be used to prevent the JWT
    // from being replayed. The jti value is a case-sensitive string.
    // Use of this claim is OPTIONAL.
    private Long jti = null;
  }

  private final Header header = new Header();
  private final Claims claims = new Claims();

  public String getType() {
    return header.typ;
  }
  public String getAlgorithm() {
    return header.alg;
  }
  public String getIssuer() {
    return claims.iss;
  }
  public String getSubject() {
    return claims.sub;
  }
  public List<String> getAudience() {
    return claims.aud;
  }
  public Long getExpires() {
    return claims.exp;
  }
  public Long getNotBefore() {
    return claims.nbf;
  }
  public Long getIssuedAt() {
    return claims.iat;
  }
  public Long getJwtId() {
    return claims.jti;
  }

  public static Builder newBuilder() {
    return new Builder();
  }

  public static class Builder {
    private JwtData jwt = new JwtData();
    public Builder setIssuer(String value) {
      jwt.claims.iss = fix(value);
      return this;
    }
    public Builder setSubject(String value) {
      jwt.claims.sub = fix(value);
      return this;
    }
    public Builder addAudience(String value) {
      if (fix(value) == null) {
        return this;
      }
      if (jwt.claims.aud == null) {
        jwt.claims.aud = new ArrayList<>();
      }
      jwt.claims.aud.add(value);
      return this;
    }
    public Builder clearAudience() {
      jwt.claims.aud = null;
      return this;
    }
    public Builder setExpires(Long value) {
      jwt.claims.exp = fix(value);
      return this;
    }
    public Builder setNotBefore(Long value) {
      jwt.claims.nbf = fix(value);
      return this;
    }
    public Builder setIssuedAt(Long value) {
      jwt.claims.iat = fix(value);
      return this;
    }
    public Builder setJwtId(Long value) {
      jwt.claims.jti = fix(value);
      return this;
    }
    public JwtData build() {
      return jwt;
    }
  }

  private static String fix(String value) {
    return Strings.emptyToNull(value);
  }

  private static Long fix(Long value) {
    if (value == null || value < 0) {
      return  null;
    }
    return value;
  }
}
