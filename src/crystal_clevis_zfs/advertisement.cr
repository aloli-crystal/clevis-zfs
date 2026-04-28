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

    # Parse a JWS advertisement and verify its self-signature using
    # one of the embedded signing keys. Supports the three RFC 7515
    # serializations:
    #
    # * **Compact** (`a.b.c`).
    # * **Flattened JSON** (RFC 7515 §7.2.2): single signature object
    #   merged into the top-level JSON.
    # * **General JSON** (RFC 7515 §7.2.1): `signatures` array of
    #   `{protected, signature}` objects. The FreeBSD `tangd` daemon
    #   emits this form when it carries multiple signing keys, e.g.
    #   after a `tangd-rotate-keys` cycle.
    def self.from_jws(jws : String) : Advertisement
      candidates = to_compact_candidates(jws)

      # Decode payload from the first candidate (any will do — the
      # payload is identical across signatures).
      info = CrystalJose::JWS.decode(candidates.first)
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

      # At least one of the (candidate, signing_key) pairs must verify.
      verified_compact = candidates.find { |c| signature_verifies?(c, signing_keys) }
      raise Error.new("advertisement signature does not match any embedded signing key") unless verified_compact

      Advertisement.new(verified_compact, signing_keys, derive_keys)
    end

    # Find a deriveKey by its thumbprint (RFC 7638).
    def find_derive_key(thumbprint_b64url : String) : CrystalJose::JWK::ECKey?
      @derive_keys.find { |k| k.thumbprint_base64url == thumbprint_b64url }
    end

    # Return one Compact JWS per signature in the input. For Compact
    # or Flattened forms there is only one candidate; for General
    # form there is one per `signatures[]` entry.
    private def self.to_compact_candidates(jws : String) : Array(String)
      jws = jws.strip
      return [jws] unless jws.starts_with?("{")

      obj = Hash(String, JSON::Any).from_json(jws)
      payload_b64 = obj["payload"]?.try(&.as_s) ||
                    raise(Error.new("JSON JWS missing 'payload'"))

      if signatures = obj["signatures"]?.try(&.as_a)
        # General JSON serialization
        raise Error.new("General JWS has empty signatures[]") if signatures.empty?
        signatures.map do |sig_any|
          sig = sig_any.as_h
          protected_b64 = sig["protected"]?.try(&.as_s) ||
                          raise(Error.new("General JWS signature missing 'protected'"))
          signature_b64 = sig["signature"]?.try(&.as_s) ||
                          raise(Error.new("General JWS signature missing 'signature'"))
          "#{protected_b64}.#{payload_b64}.#{signature_b64}"
        end
      else
        # Flattened JSON serialization
        protected_b64 = obj["protected"]?.try(&.as_s) ||
                        raise(Error.new("Flattened JWS missing 'protected' header"))
        signature_b64 = obj["signature"]?.try(&.as_s) ||
                        raise(Error.new("Flattened JWS missing 'signature'"))
        ["#{protected_b64}.#{payload_b64}.#{signature_b64}"]
      end
    end

    # True if some signing key verifies the Compact JWS `jws`.
    private def self.signature_verifies?(jws : String,
                                         signing_keys : Array(CrystalJose::JWK::ECKey)) : Bool
      info = CrystalJose::JWS.decode(jws)
      alg_str = info[:header]["alg"]?.try(&.as_s)
      return false unless alg_str
      alg = CrystalJose::JWS::Algorithm.from_name(alg_str)

      signing_keys.any? do |k|
        next false unless k.curve == alg.curve
        begin
          CrystalJose::JWS.verify(jws, k)
          true
        rescue CrystalJose::JWS::VerificationError
          false
        end
      end
    rescue CrystalJose::JWS::UnsupportedAlgorithmError
      false
    end

    private def self.uses_for(key_hash : Hash(String, JSON::Any)) : Array(String)
      ops = key_hash["key_ops"]?
      return [] of String unless ops
      ops.as_a.map(&.as_s)
    end
  end
end
