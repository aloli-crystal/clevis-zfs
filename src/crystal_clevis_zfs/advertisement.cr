require "json"
require "crystal-jose"

module CrystalClevisZfs
  # Parsed Tang advertisement: a JWS Compact whose payload is a JWKSet.
  #
  # The JWKSet contains keys for two purposes:
  #   * `use: "sig"` (or `key_ops: ["verify"]`) — used to verify the
  #     signature of the advertisement itself (self-signed).
  #   * `use: "deriveKey"` (or `key_ops: ["deriveKey"]`) — used by the
  #     Tang protocol to perform ECDH agreements.
  class Advertisement
    class Error < Exception
    end

    getter raw_jws : String
    getter signing_keys : Array(CrystalJose::JWK::ECKey)
    getter derive_keys : Array(CrystalJose::JWK::ECKey)

    def initialize(@raw_jws : String, @signing_keys : Array(CrystalJose::JWK::ECKey),
                   @derive_keys : Array(CrystalJose::JWK::ECKey))
    end

    # Parse a JWS advertisement (Compact or Flattened JSON form, per
    # RFC 7515 §7.2.2 — the FreeBSD `tangd` daemon emits the latter)
    # and verify its self-signature using one of the embedded signing
    # keys.
    def self.from_jws(jws : String) : Advertisement
      jws = compactify_if_flattened(jws)
      info = CrystalJose::JWS.decode(jws)
      payload_str = String.new(info[:payload])
      jwks = Hash(String, JSON::Any).from_json(payload_str)
      keys_array = jwks["keys"]?.try(&.as_a) || raise(Error.new("advertisement payload is not a JWKSet"))

      signing_keys = [] of CrystalJose::JWK::ECKey
      derive_keys = [] of CrystalJose::JWK::ECKey

      keys_array.each do |key_any|
        key_hash = {} of String => JSON::Any
        key_any.as_h.each { |k, v| key_hash[k] = v }
        next unless key_hash["kty"]?.try(&.as_s) == "EC"

        ec_key = CrystalJose::JWK::ECKey.from_jwk_hash(key_hash)
        if uses_for(key_hash).includes?("verify") || key_hash["use"]?.try(&.as_s) == "sig"
          signing_keys << ec_key
        end
        if uses_for(key_hash).includes?("deriveKey") || key_hash["use"]?.try(&.as_s) == "deriveKey"
          derive_keys << ec_key
        end
      end

      raise Error.new("advertisement contains no signing key") if signing_keys.empty?
      raise Error.new("advertisement contains no deriveKey") if derive_keys.empty?

      verify_self_signature!(jws, signing_keys)

      Advertisement.new(jws, signing_keys, derive_keys)
    end

    # Find a deriveKey by its thumbprint (RFC 7638).
    def find_derive_key(thumbprint_b64url : String) : CrystalJose::JWK::ECKey?
      @derive_keys.find { |k| k.thumbprint_base64url == thumbprint_b64url }
    end

    # Convert a JWS in Flattened JSON Serialization (RFC 7515 §7.2.2)
    # to Compact Serialization. A Compact-form input is returned as is.
    private def self.compactify_if_flattened(jws : String) : String
      jws = jws.strip
      return jws unless jws.starts_with?("{")

      obj = Hash(String, JSON::Any).from_json(jws)
      protected_b64 = obj["protected"]?.try(&.as_s) ||
                      raise(Error.new("Flattened JWS missing 'protected' header"))
      payload_b64 = obj["payload"]?.try(&.as_s) ||
                    raise(Error.new("Flattened JWS missing 'payload'"))
      signature_b64 = obj["signature"]?.try(&.as_s) ||
                      raise(Error.new("Flattened JWS missing 'signature'"))

      "#{protected_b64}.#{payload_b64}.#{signature_b64}"
    end

    private def self.uses_for(key_hash : Hash(String, JSON::Any)) : Array(String)
      ops = key_hash["key_ops"]?
      return [] of String unless ops
      ops.as_a.map(&.as_s)
    end

    # Verify the advertisement is signed by one of the embedded
    # signing keys (Tang advertisements are self-signed).
    private def self.verify_self_signature!(jws : String, signing_keys : Array(CrystalJose::JWK::ECKey))
      info = CrystalJose::JWS.decode(jws)
      header = info[:header]
      alg = header["alg"]?.try(&.as_s) || raise(Error.new("missing alg in advertisement JWS header"))

      # Try every signing key — Tang doesn't always include a kid.
      verified = signing_keys.any? do |k|
        next false unless k.curve == CrystalJose::JWS::Algorithm.from_name(alg).curve
        begin
          CrystalJose::JWS.verify(jws, k)
          true
        rescue CrystalJose::JWS::VerificationError
          false
        end
      end

      raise Error.new("advertisement signature does not match any embedded signing key") unless verified
    end
  end
end
