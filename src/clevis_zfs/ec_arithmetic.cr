require "jose"
require "./openssl_ext"

module ClevisZfs
  # High-level EC point arithmetic on top of the OpenSSL bindings.
  # All operations are pure-function, returning a fresh ECKey holding
  # only the public coordinates (no `d`).
  module ECArithmetic
    extend self

    class Error < Exception
    end

    # Add two public-key points on the same curve. Returns a public-only
    # ECKey with the resulting (x, y) coordinates.
    def add(a : Jose::JWK::ECKey, b : Jose::JWK::ECKey) : Jose::JWK::ECKey
      raise Error.new("curve mismatch") if a.curve != b.curve

      ec_a = build_ec_key(a)
      ec_b = build_ec_key(b)
      group = LibCrypto.ec_key_get0_group(ec_a)
      bn_ctx = LibCrypto.bn_ctx_new
      result = LibCrypto.ec_point_new(group)

      begin
        pt_a = LibCrypto.ec_key_get0_public_key(ec_a)
        pt_b = LibCrypto.ec_key_get0_public_key(ec_b)
        if LibCrypto.ec_point_add(group, result, pt_a, pt_b, bn_ctx) != 1
          raise Error.new("EC_POINT_add failed")
        end
        if LibCrypto.ec_point_is_at_infinity(group, result) == 1
          raise Error.new("EC_POINT_add produced point at infinity")
        end
        point_to_eckey(result, group, a.curve, bn_ctx)
      ensure
        LibCrypto.ec_point_free(result)
        LibCrypto.bn_ctx_free(bn_ctx)
        LibCrypto.ec_key_free(ec_a)
        LibCrypto.ec_key_free(ec_b)
      end
    end

    # Subtract: result = a - b. Implemented as a + (-b).
    def subtract(a : Jose::JWK::ECKey, b : Jose::JWK::ECKey) : Jose::JWK::ECKey
      raise Error.new("curve mismatch") if a.curve != b.curve

      ec_a = build_ec_key(a)
      ec_b = build_ec_key(b)
      group = LibCrypto.ec_key_get0_group(ec_a)
      bn_ctx = LibCrypto.bn_ctx_new
      result = LibCrypto.ec_point_new(group)
      neg_b = LibCrypto.ec_point_dup(LibCrypto.ec_key_get0_public_key(ec_b), group)

      begin
        if LibCrypto.ec_point_invert(group, neg_b, bn_ctx) != 1
          raise Error.new("EC_POINT_invert failed")
        end
        pt_a = LibCrypto.ec_key_get0_public_key(ec_a)
        if LibCrypto.ec_point_add(group, result, pt_a, neg_b, bn_ctx) != 1
          raise Error.new("EC_POINT_add failed")
        end
        if LibCrypto.ec_point_is_at_infinity(group, result) == 1
          raise Error.new("subtract produced point at infinity")
        end
        point_to_eckey(result, group, a.curve, bn_ctx)
      ensure
        LibCrypto.ec_point_free(neg_b)
        LibCrypto.ec_point_free(result)
        LibCrypto.bn_ctx_free(bn_ctx)
        LibCrypto.ec_key_free(ec_a)
        LibCrypto.ec_key_free(ec_b)
      end
    end

    # Scalar multiplication: result = scalar * point.
    # `scalar_priv` provides the scalar via its `d` component.
    def scalar_mul(scalar_priv : Jose::JWK::ECKey, point : Jose::JWK::ECKey) : Jose::JWK::ECKey
      raise Error.new("curve mismatch") if scalar_priv.curve != point.curve
      raise Error.new("scalar must come from a private key (d)") unless scalar_priv.private?

      ec_point = build_ec_key(point)
      ec_scalar = build_ec_key(scalar_priv)
      group = LibCrypto.ec_key_get0_group(ec_point)
      bn_ctx = LibCrypto.bn_ctx_new
      result = LibCrypto.ec_point_new(group)

      begin
        bn_d = LibCrypto.ec_key_get0_private_key(ec_scalar)
        pt = LibCrypto.ec_key_get0_public_key(ec_point)
        if LibCrypto.ec_point_mul(group, result, Pointer(Void).null.as(LibCrypto::Bignum), pt, bn_d, bn_ctx) != 1
          raise Error.new("EC_POINT_mul failed")
        end
        if LibCrypto.ec_point_is_at_infinity(group, result) == 1
          raise Error.new("scalar_mul produced point at infinity")
        end
        point_to_eckey(result, group, point.curve, bn_ctx)
      ensure
        LibCrypto.ec_point_free(result)
        LibCrypto.bn_ctx_free(bn_ctx)
        LibCrypto.ec_key_free(ec_point)
        LibCrypto.ec_key_free(ec_scalar)
      end
    end

    private def build_ec_key(jwk : Jose::JWK::ECKey) : LibCrypto::EC_KEY
      ec_key = LibCrypto.ec_key_new_by_curve_name(jwk.curve.nid)
      raise Error.new("EC_KEY_new_by_curve_name failed") if ec_key.null?

      bn_ctx = LibCrypto.bn_ctx_new
      bn_x = LibCrypto.bn_bin2bn(jwk.x.to_unsafe, jwk.x.size, Pointer(Void).null.as(LibCrypto::Bignum))
      bn_y = LibCrypto.bn_bin2bn(jwk.y.to_unsafe, jwk.y.size, Pointer(Void).null.as(LibCrypto::Bignum))
      group = LibCrypto.ec_key_get0_group(ec_key)
      point = LibCrypto.ec_point_new(group)

      begin
        if LibCrypto.ec_point_set_affine_coordinates(group, point, bn_x, bn_y, bn_ctx) != 1
          raise Error.new("EC_POINT_set_affine_coordinates failed")
        end
        if LibCrypto.ec_key_set_public_key(ec_key, point) != 1
          raise Error.new("EC_KEY_set_public_key failed")
        end
        if priv = jwk.d
          bn_d = LibCrypto.bn_bin2bn(priv.to_unsafe, priv.size, Pointer(Void).null.as(LibCrypto::Bignum))
          begin
            if LibCrypto.ec_key_set_private_key(ec_key, bn_d) != 1
              raise Error.new("EC_KEY_set_private_key failed")
            end
          ensure
            LibCrypto.bn_free(bn_d)
          end
        end
        ec_key
      rescue ex
        LibCrypto.ec_key_free(ec_key)
        raise ex
      ensure
        LibCrypto.ec_point_free(point) unless point.null?
        LibCrypto.bn_free(bn_x) unless bn_x.null?
        LibCrypto.bn_free(bn_y) unless bn_y.null?
        LibCrypto.bn_ctx_free(bn_ctx) unless bn_ctx.null?
      end
    end

    private def point_to_eckey(point : LibCrypto::EcPoint, group : LibCrypto::EcGroup,
                               curve : Jose::JWK::Curve, bn_ctx : LibCrypto::BignumCtx) : Jose::JWK::ECKey
      bn_x = LibCrypto.bn_new
      bn_y = LibCrypto.bn_new
      begin
        if LibCrypto.ec_point_get_affine_coordinates(group, point, bn_x, bn_y, bn_ctx) != 1
          raise Error.new("EC_POINT_get_affine_coordinates failed")
        end
        coord_len = curve.coordinate_octet_length
        x_bytes = Bytes.new(coord_len)
        y_bytes = Bytes.new(coord_len)
        if LibCrypto.bn_bn2binpad(bn_x, x_bytes.to_unsafe, coord_len) != coord_len
          raise Error.new("BN_bn2binpad(x) failed")
        end
        if LibCrypto.bn_bn2binpad(bn_y, y_bytes.to_unsafe, coord_len) != coord_len
          raise Error.new("BN_bn2binpad(y) failed")
        end
        Jose::JWK::ECKey.new(curve, x_bytes, y_bytes)
      ensure
        LibCrypto.bn_free(bn_x)
        LibCrypto.bn_free(bn_y)
      end
    end
  end
end
