require "http/client"
require "uri"
require "json"
require "jose"

require "./advertisement"
require "./ec_arithmetic"

module ClevisZfs
  # Talks to a Tang server over HTTP.
  #
  # `bind` does not contact the server beyond fetching its
  # advertisement: the encryption is performed locally with the
  # advertised public key. `recover` does talk to `/rec/<kid>`.
  class TangClient
    class Error < Exception
    end

    getter url : String

    # Fetched lazily on first use; can be supplied explicitly for
    # testing or for reading a stored advertisement at recover time.
    @advertisement : Advertisement?

    def initialize(@url : String, @advertisement : Advertisement? = nil)
    end

    # Returns the cached advertisement, fetching from the server if needed.
    def advertisement : Advertisement
      @advertisement ||= fetch_advertisement
    end

    # Encrypt `plaintext` using the Tang server's deriveKey (no
    # network call beyond fetching the advertisement). Returns a JWE
    # Compact carrying the `clevis.tang` claim that allows recovery later.
    #
    # If `derive_key` is not given, the first deriveKey from the
    # advertisement is used.
    def bind(plaintext : Bytes | String,
             derive_key : Jose::JWK::ECKey? = nil) : String
      adv = advertisement
      key = derive_key || adv.derive_keys.first
      raise Error.new("derive key is not in advertisement") unless adv.derive_keys.any? { |k| k.thumbprint_base64url == key.thumbprint_base64url }
      raise Error.new("derive key must be public") if key.private?

      ephemeral = Jose::JWK::ECKey.generate(key.curve)

      # Use the JOSE primitives directly: ECDH(c, S) + Concat KDF -> CEK.
      # We re-do the JWE construction ourselves rather than calling
      # Jose::JWE.encrypt, because we want to embed extra
      # `clevis.tang` claims in the protected header.
      shared = Jose::JWE.ecdh_derive(ephemeral, key)
      cek = Jose::JWE.concat_kdf_a256gcm(shared)

      header = {} of String => JSON::Any
      header["alg"] = JSON::Any.new("ECDH-ES")
      header["enc"] = JSON::Any.new("A256GCM")
      header["kid"] = JSON::Any.new(key.thumbprint_base64url)
      header["epk"] = JSON::Any.new(eckey_to_any(ephemeral.public_key))

      clevis_claim = {} of String => JSON::Any
      clevis_claim["pin"] = JSON::Any.new("tang")
      tang_claim = {} of String => JSON::Any
      tang_claim["url"] = JSON::Any.new(@url)
      tang_claim["adv"] = JSON::Any.new(parse_advertisement_jwks(adv.raw_jws))
      clevis_claim["tang"] = JSON::Any.new(tang_claim)
      header["clevis"] = JSON::Any.new(clevis_claim)

      bytes = plaintext.is_a?(String) ? plaintext.to_slice : plaintext
      header_b64 = Jose::Utils.base64url_encode(header.to_json)
      iv = Random::Secure.random_bytes(Jose::JWE::GCM_IV_BYTES)
      aad = header_b64.to_slice
      ciphertext, tag = aes_256_gcm_encrypt(cek, iv, aad, bytes)

      [
        header_b64,
        "",
        Jose::Utils.base64url_encode(iv),
        Jose::Utils.base64url_encode(ciphertext),
        Jose::Utils.base64url_encode(tag),
      ].join('.')
    end

    # Decrypt a JWE that was produced by `bind`. Performs the Tang
    # recovery dance: posts the masked ephemeral point to the server
    # and reconstructs the shared secret from the response.
    def recover(jwe : String) : Bytes
      header_b64, _enc_key, iv_b64, ct_b64, tag_b64 = split_compact(jwe)
      header = Hash(String, JSON::Any).from_json(String.new(Jose::Utils.base64url_decode(header_b64)))

      alg = header["alg"]?.try(&.as_s)
      enc = header["enc"]?.try(&.as_s)
      raise Error.new("unsupported alg: #{alg}") unless alg == "ECDH-ES"
      raise Error.new("unsupported enc: #{enc}") unless enc == "A256GCM"

      kid = header["kid"]?.try(&.as_s) || raise(Error.new("missing kid"))
      epk_any = header["epk"]? || raise(Error.new("missing epk"))
      epk_hash = {} of String => JSON::Any
      epk_any.as_h.each { |k, v| epk_hash[k] = v }
      epk = Jose::JWK::ECKey.from_jwk_hash(epk_hash)

      adv = advertisement
      derive_key = adv.find_derive_key(kid) ||
                   raise(Error.new("kid #{kid} not found in advertisement"))
      raise Error.new("epk curve does not match deriveKey") if epk.curve != derive_key.curve

      # Recovery dance.
      # We want to recompute K_point = epk.priv * derive_key (the
      # original ECDH product). Tang holds derive_key.priv (= s); we
      # only have epk (= C). We mask C with a fresh ephemeral E:
      #   X = C + E
      # Tang returns Y = s * X = s.C + s.E.
      # We compute K_point = Y - e.S, which equals s.C because s.E = e.S.
      ephemeral = Jose::JWK::ECKey.generate(derive_key.curve)
      x_point = ECArithmetic.add(epk, ephemeral.public_key)

      y_point = post_recover(kid, x_point)
      raise Error.new("server returned a point on a different curve") if y_point.curve != derive_key.curve

      e_s = ECArithmetic.scalar_mul(ephemeral, derive_key)
      k_point = ECArithmetic.subtract(y_point, e_s)

      # The shared secret is the X-coordinate of K_point (per JWA
      # ECDH-ES: the raw shared secret Z is the X coord of the result).
      shared = k_point.x
      cek = Jose::JWE.concat_kdf_a256gcm(shared)

      iv = Jose::Utils.base64url_decode(iv_b64)
      ct = Jose::Utils.base64url_decode(ct_b64)
      tag = Jose::Utils.base64url_decode(tag_b64)
      raise Error.new("iv has wrong length") unless iv.size == Jose::JWE::GCM_IV_BYTES
      raise Error.new("tag has wrong length") unless tag.size == Jose::JWE::GCM_TAG_BYTES

      aes_256_gcm_decrypt(cek, iv, header_b64.to_slice, ct, tag)
    end

    # Override this in a subclass (or stub Process for HTTP) to test
    # without a live Tang server.
    protected def fetch_advertisement : Advertisement
      response = HTTP::Client.get("#{@url.chomp('/')}/adv")
      raise Error.new("advertisement fetch failed: HTTP #{response.status_code}") unless response.success?
      Advertisement.from_jws(response.body.strip)
    end

    protected def post_recover(kid : String, x_point : Jose::JWK::ECKey) : Jose::JWK::ECKey
      body = eckey_jwk_json(x_point)
      headers = HTTP::Headers{"Content-Type" => "application/jwk+json"}
      response = HTTP::Client.post("#{@url.chomp('/')}/rec/#{kid}", headers: headers, body: body)
      raise Error.new("recover failed: HTTP #{response.status_code}") unless response.success?
      Jose::JWK::ECKey.from_json(response.body.strip)
    end

    private def split_compact(jwe : String) : Tuple(String, String, String, String, String)
      parts = jwe.split('.')
      raise Error.new("JWE Compact must have 5 parts, got #{parts.size}") unless parts.size == 5
      {parts[0], parts[1], parts[2], parts[3], parts[4]}
    end

    private def parse_advertisement_jwks(adv_jws : String) : Hash(String, JSON::Any)
      info = Jose::JWS.decode(adv_jws)
      Hash(String, JSON::Any).from_json(String.new(info[:payload]))
    end

    private def eckey_to_any(key : Jose::JWK::ECKey) : Hash(String, JSON::Any)
      result = {} of String => JSON::Any
      key.to_jwk_hash.each { |k, v| result[k] = JSON::Any.new(v) }
      result
    end

    private def eckey_jwk_json(key : Jose::JWK::ECKey) : String
      eckey_to_any(key).to_json
    end

    # Local copies of the AES-GCM helpers from Jose::JWE,
    # because we need to drive the cipher with our own AAD here.
    private def aes_256_gcm_encrypt(key : Bytes, iv : Bytes, aad : Bytes, plaintext : Bytes) : Tuple(Bytes, Bytes)
      ctx = LibCrypto.evp_cipher_ctx_new
      begin
        cipher = LibCrypto.evp_aes_256_gcm
        if LibCrypto.evp_cipherinit_ex(ctx, cipher, nil, Pointer(UInt8).null, Pointer(UInt8).null, 1) != 1
          raise Error.new("EVP_CipherInit_ex (encrypt) failed")
        end
        if LibCrypto.evp_cipher_ctx_ctrl(ctx, LibCrypto::EVP_CTRL_GCM_SET_IVLEN, iv.size, Pointer(Void).null) != 1
          raise Error.new("EVP_CIPHER_CTX_ctrl(SET_IVLEN) failed")
        end
        if LibCrypto.evp_cipherinit_ex(ctx, Pointer(Void).null.as(LibCrypto::EVP_CIPHER), nil, key.to_unsafe, iv.to_unsafe, 1) != 1
          raise Error.new("EVP_CipherInit_ex (encrypt key/iv) failed")
        end

        outlen = 0_i32
        unless aad.empty?
          if LibCrypto.evp_cipherupdate(ctx, Pointer(UInt8).null, pointerof(outlen), aad.to_unsafe, aad.size) != 1
            raise Error.new("EVP_CipherUpdate (AAD) failed")
          end
        end

        ciphertext = Bytes.new(plaintext.size)
        if LibCrypto.evp_cipherupdate(ctx, ciphertext.to_unsafe, pointerof(outlen), plaintext.to_unsafe, plaintext.size) != 1
          raise Error.new("EVP_CipherUpdate (plaintext) failed")
        end
        produced = outlen
        final_buf = Bytes.new(16)
        if LibCrypto.evp_cipherfinal_ex(ctx, final_buf.to_unsafe, pointerof(outlen)) != 1
          raise Error.new("EVP_CipherFinal_ex failed")
        end
        produced += outlen

        tag = Bytes.new(Jose::JWE::GCM_TAG_BYTES)
        if LibCrypto.evp_cipher_ctx_ctrl(ctx, LibCrypto::EVP_CTRL_GCM_GET_TAG, Jose::JWE::GCM_TAG_BYTES, tag.to_unsafe.as(Void*)) != 1
          raise Error.new("EVP_CIPHER_CTX_ctrl(GET_TAG) failed")
        end

        {ciphertext[0, produced], tag}
      ensure
        LibCrypto.evp_cipher_ctx_free(ctx)
      end
    end

    private def aes_256_gcm_decrypt(key : Bytes, iv : Bytes, aad : Bytes, ciphertext : Bytes, tag : Bytes) : Bytes
      ctx = LibCrypto.evp_cipher_ctx_new
      begin
        cipher = LibCrypto.evp_aes_256_gcm
        if LibCrypto.evp_cipherinit_ex(ctx, cipher, nil, Pointer(UInt8).null, Pointer(UInt8).null, 0) != 1
          raise Error.new("EVP_CipherInit_ex (decrypt) failed")
        end
        if LibCrypto.evp_cipher_ctx_ctrl(ctx, LibCrypto::EVP_CTRL_GCM_SET_IVLEN, iv.size, Pointer(Void).null) != 1
          raise Error.new("EVP_CIPHER_CTX_ctrl(SET_IVLEN) failed")
        end
        if LibCrypto.evp_cipherinit_ex(ctx, Pointer(Void).null.as(LibCrypto::EVP_CIPHER), nil, key.to_unsafe, iv.to_unsafe, 0) != 1
          raise Error.new("EVP_CipherInit_ex (decrypt key/iv) failed")
        end

        outlen = 0_i32
        unless aad.empty?
          if LibCrypto.evp_cipherupdate(ctx, Pointer(UInt8).null, pointerof(outlen), aad.to_unsafe, aad.size) != 1
            raise Error.new("EVP_CipherUpdate (AAD) failed")
          end
        end

        plaintext = Bytes.new(ciphertext.size)
        if LibCrypto.evp_cipherupdate(ctx, plaintext.to_unsafe, pointerof(outlen), ciphertext.to_unsafe, ciphertext.size) != 1
          raise Error.new("EVP_CipherUpdate (ciphertext) failed")
        end
        produced = outlen

        if LibCrypto.evp_cipher_ctx_ctrl(ctx, LibCrypto::EVP_CTRL_GCM_SET_TAG, tag.size, tag.to_unsafe.as(Void*)) != 1
          raise Error.new("EVP_CIPHER_CTX_ctrl(SET_TAG) failed")
        end

        final_buf = Bytes.new(16)
        if LibCrypto.evp_cipherfinal_ex(ctx, final_buf.to_unsafe, pointerof(outlen)) != 1
          raise Error.new("authentication tag mismatch")
        end
        produced += outlen

        plaintext[0, produced]
      ensure
        LibCrypto.evp_cipher_ctx_free(ctx)
      end
    end
  end
end
