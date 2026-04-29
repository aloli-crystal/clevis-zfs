require "json"
require "random/secure"
require "jose"

require "./openssl_ext"
require "./sss"
require "./tang_client"

module ClevisZfs
  # High-level multi-Tang bind/recover wrapping Shamir Secret Sharing.
  #
  # Format: a JWE with `alg: "dir"`, `enc: "A256GCM"` whose protected
  # header carries a `clevis.sss` object compatible with the Clevis
  # latchset format:
  #
  #   { "alg": "dir", "enc": "A256GCM",
  #     "clevis": { "pin": "sss",
  #                 "sss": { "t": K,
  #                          "p": "<base64url prime>",
  #                          "jwe": [<sub_jwe_compact>, ...] } } }
  #
  # Each sub-JWE is a regular Tang JWE (ECDH-ES + A256GCM) whose
  # decrypted plaintext is the bytes `x || y` of one Shamir point.
  module SssBinder
    extend self

    class Error < Exception
    end

    SECRET_BYTES = 32 # A256GCM CEK length
    GCM_IV_BYTES = Jose::JWE::GCM_IV_BYTES
    GCM_TAG      = Jose::JWE::GCM_TAG_BYTES

    # Convenience overload: build TangClient from URLs and bind.
    def bind(plaintext : Bytes | String, tang_urls : Array(String), threshold : Int32) : String
      bind(plaintext, tang_urls.map { |u| TangClient.new(u) }, threshold)
    end

    # Encrypt `plaintext` against the given TangClients with threshold K.
    # The resulting JWE can be decrypted using any K of the N Tangs.
    def bind(plaintext : Bytes | String, tangs : Array(TangClient), threshold : Int32) : String
      bytes = plaintext.is_a?(String) ? plaintext.to_slice : plaintext
      raise Error.new("at least one Tang client is required") if tangs.empty?
      raise Error.new("threshold must be >= 1") if threshold < 1
      raise Error.new("threshold cannot exceed the number of Tangs (#{tangs.size})") if threshold > tangs.size

      cek = Random::Secure.random_bytes(SECRET_BYTES)
      split = Sss.split(cek, threshold: threshold, count: tangs.size)

      sub_jwes = Array(String).new(tangs.size)
      tangs.each_with_index do |tang, i|
        point = split.points[i]
        # JWK octet payload that the sub-JWE will encrypt.
        jwk = {
          "kty" => "oct",
          "k"   => Jose::Utils.base64url_encode(concat(point.x, point.y)),
        }
        sub_jwes << tang.bind(jwk.to_json)
      end

      header = {} of String => JSON::Any
      header["alg"] = JSON::Any.new("dir")
      header["enc"] = JSON::Any.new("A256GCM")

      sss_obj = {} of String => JSON::Any
      sss_obj["t"] = JSON::Any.new(threshold.to_i64)
      sss_obj["p"] = JSON::Any.new(Jose::Utils.base64url_encode(split.prime))
      sss_obj["jwe"] = JSON::Any.new(sub_jwes.map { |j| JSON::Any.new(j) })

      clevis = {} of String => JSON::Any
      clevis["pin"] = JSON::Any.new("sss")
      clevis["sss"] = JSON::Any.new(sss_obj)
      header["clevis"] = JSON::Any.new(clevis)

      header_b64 = Jose::Utils.base64url_encode(header.to_json)
      iv = Random::Secure.random_bytes(GCM_IV_BYTES)
      aad = header_b64.to_slice
      ciphertext, tag = aes_gcm_encrypt(cek, iv, aad, bytes)

      [
        header_b64,
        "",
        Jose::Utils.base64url_encode(iv),
        Jose::Utils.base64url_encode(ciphertext),
        Jose::Utils.base64url_encode(tag),
      ].join('.')
    end

    # Decrypt an outer JWE produced by `bind`. Tries each sub-JWE in
    # order and stops as soon as `threshold` of them succeed. The
    # optional `tang_factory` block lets callers (mostly tests) build
    # custom TangClient instances from URLs.
    def recover(jwe : String, &tang_factory : String -> TangClient) : Bytes
      recover_inner(jwe, tang_factory)
    end

    def recover(jwe : String) : Bytes
      recover_inner(jwe, ->(url : String) { TangClient.new(url) })
    end

    private def recover_inner(jwe : String, tang_factory : String -> TangClient) : Bytes
      header_b64, _enc_key, iv_b64, ct_b64, tag_b64 = split_compact(jwe)
      header = Hash(String, JSON::Any).from_json(String.new(Jose::Utils.base64url_decode(header_b64)))

      alg = header["alg"]?.try(&.as_s) || raise(Error.new("missing alg"))
      enc = header["enc"]?.try(&.as_s) || raise(Error.new("missing enc"))
      raise Error.new("expected alg=dir, got #{alg}") unless alg == "dir"
      raise Error.new("expected enc=A256GCM, got #{enc}") unless enc == "A256GCM"

      clevis = header["clevis"]?.try(&.as_h) || raise(Error.new("missing clevis claim"))
      raise Error.new("expected pin=sss, got #{clevis["pin"]?}") unless clevis["pin"]?.try(&.as_s) == "sss"
      sss = clevis["sss"]?.try(&.as_h) || raise(Error.new("missing clevis.sss"))

      threshold = sss["t"]?.try(&.as_i) || raise(Error.new("missing clevis.sss.t"))
      prime_b64 = sss["p"]?.try(&.as_s) || raise(Error.new("missing clevis.sss.p"))
      prime = Jose::Utils.base64url_decode(prime_b64)
      sub_jwes = sss["jwe"]?.try(&.as_a) || raise(Error.new("missing clevis.sss.jwe"))

      coord_len = prime.size

      points = [] of Sss::Point
      errors = [] of String
      sub_jwes.each do |sub_any|
        break if points.size >= threshold
        sub_jwe = sub_any.as_s
        begin
          point_bytes = recover_one_point(sub_jwe, tang_factory)
          unless point_bytes.size == 2 * coord_len
            raise Error.new("sub-JWE point has wrong length (#{point_bytes.size}, expected #{2 * coord_len})")
          end
          x = point_bytes[0, coord_len]
          y = point_bytes[coord_len, coord_len]
          points << Sss::Point.new(x: x, y: y)
        rescue ex
          errors << ex.message.to_s
        end
      end

      if points.size < threshold
        raise Error.new("recovered only #{points.size} / #{threshold} required shares (errors: #{errors.join("; ")})")
      end

      cek = Sss.recover(prime, points, secret_size: SECRET_BYTES)

      iv = Jose::Utils.base64url_decode(iv_b64)
      ct = Jose::Utils.base64url_decode(ct_b64)
      tag = Jose::Utils.base64url_decode(tag_b64)
      raise Error.new("iv has wrong length") unless iv.size == GCM_IV_BYTES
      raise Error.new("tag has wrong length") unless tag.size == GCM_TAG

      aes_gcm_decrypt(cek, iv, header_b64.to_slice, ct, tag)
    end

    # True if the JWE protected header announces clevis.pin = sss.
    def self.is_sss?(jwe : String) : Bool
      header_b64 = jwe.split('.').first
      header = Hash(String, JSON::Any).from_json(String.new(Jose::Utils.base64url_decode(header_b64)))
      clevis = header["clevis"]?.try(&.as_h)
      return false unless clevis
      clevis["pin"]?.try(&.as_s) == "sss"
    rescue
      false
    end

    private def recover_one_point(sub_jwe : String, tang_factory : String -> TangClient) : Bytes
      # The sub-JWE carries clevis.tang.url in its header — we look it
      # up to know which Tang to talk to, then ask the factory to build
      # the matching client.
      header_b64 = sub_jwe.split('.').first
      header = Hash(String, JSON::Any).from_json(String.new(Jose::Utils.base64url_decode(header_b64)))
      clevis = header["clevis"]?.try(&.as_h) || raise(Error.new("sub-JWE missing clevis claim"))
      tang = clevis["tang"]?.try(&.as_h) || raise(Error.new("sub-JWE clevis claim is not a tang pin"))
      url = tang["url"]?.try(&.as_s) || raise(Error.new("sub-JWE missing clevis.tang.url"))

      client = tang_factory.call(url)
      jwk_bytes = client.recover(sub_jwe)
      jwk = Hash(String, JSON::Any).from_json(String.new(jwk_bytes))
      raise Error.new("sub-JWE plaintext is not a JWK") unless jwk["kty"]?.try(&.as_s) == "oct"
      k_b64 = jwk["k"]?.try(&.as_s) || raise(Error.new("sub-JWE JWK missing 'k'"))
      Jose::Utils.base64url_decode(k_b64)
    end

    private def split_compact(jwe : String) : Tuple(String, String, String, String, String)
      parts = jwe.split('.')
      raise Error.new("JWE Compact must have 5 parts, got #{parts.size}") unless parts.size == 5
      {parts[0], parts[1], parts[2], parts[3], parts[4]}
    end

    private def concat(a : Bytes, b : Bytes) : Bytes
      result = Bytes.new(a.size + b.size)
      a.copy_to(result[0, a.size])
      b.copy_to(result[a.size, b.size])
      result
    end

    private def aes_gcm_encrypt(key : Bytes, iv : Bytes, aad : Bytes, plaintext : Bytes) : Tuple(Bytes, Bytes)
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

        tag = Bytes.new(GCM_TAG)
        if LibCrypto.evp_cipher_ctx_ctrl(ctx, LibCrypto::EVP_CTRL_GCM_GET_TAG, GCM_TAG, tag.to_unsafe.as(Void*)) != 1
          raise Error.new("EVP_CIPHER_CTX_ctrl(GET_TAG) failed")
        end

        {ciphertext[0, produced], tag}
      ensure
        LibCrypto.evp_cipher_ctx_free(ctx)
      end
    end

    private def aes_gcm_decrypt(key : Bytes, iv : Bytes, aad : Bytes, ciphertext : Bytes, tag : Bytes) : Bytes
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
