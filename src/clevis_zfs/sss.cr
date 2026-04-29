require "random/secure"
require "./openssl_ext"

module ClevisZfs
  # Shamir Secret Sharing over GF(p), with p a fresh random prime
  # generated per split. Format and conventions match Clevis (latchset)
  # so that interoperability with `clevis encrypt sss` remains
  # achievable.
  #
  # The polynomial is f(x) = a₀ + a₁·x + … + a_{K-1}·x^{K-1} mod p,
  # where a₀ is the secret. Each share is a point (x_i, f(x_i)) with
  # distinct, non-zero x_i. With any K of the N shares, Lagrange
  # interpolation at X=0 recovers a₀.
  module Sss
    extend self

    class Error < Exception
    end

    PRIME_BITS = 256

    record Point, x : Bytes, y : Bytes

    record SplitResult,
      prime : Bytes,
      threshold : Int32,
      points : Array(Point)

    # Split `secret` into `count` shares such that any `threshold` of
    # them can reconstruct it. Returns the prime used and the list of
    # points. Re-tries the prime generation if the secret happens to
    # be >= p (rare for a 256-bit secret with a 256-bit prime, but
    # possible).
    def split(secret : Bytes, threshold : Int32, count : Int32) : SplitResult
      raise Error.new("threshold must be >= 1") if threshold < 1
      raise Error.new("count must be >= threshold") if count < threshold
      raise Error.new("threshold > 255 not supported (x_i must fit in one byte)") if count > 255

      ctx = LibCrypto.bn_ctx_new
      raise Error.new("BN_CTX_new failed") if ctx.null?
      bns_to_free = [] of LibCrypto::Bignum

      begin
        secret_bn = bn_from_bytes(secret)
        bns_to_free << secret_bn

        prime = LibCrypto.bn_new
        bns_to_free << prime
        loop do
          if LibCrypto.bn_generate_prime_ex(prime, PRIME_BITS, 1, Pointer(Void).null.as(LibCrypto::Bignum), Pointer(Void).null.as(LibCrypto::Bignum), Pointer(Void).null) != 1
            raise Error.new("BN_generate_prime_ex failed")
          end
          break if LibCrypto.bn_cmp(secret_bn, prime) < 0
        end

        # Build the polynomial coefficients [a₀=secret, a₁, …, a_{K-1}].
        coeffs = Array(LibCrypto::Bignum).new(threshold)
        coeffs << secret_bn
        (threshold - 1).times do
          c = LibCrypto.bn_new
          bns_to_free << c
          if LibCrypto.bn_rand_range(c, prime) != 1
            raise Error.new("BN_rand_range failed")
          end
          coeffs << c
        end

        # Evaluate at x = 1, 2, …, count.
        points = Array(Point).new(count)
        (1..count).each do |x_int|
          x_bn = LibCrypto.bn_new
          bns_to_free << x_bn
          if LibCrypto.bn_set_word(x_bn, x_int.to_u64) != 1
            raise Error.new("BN_set_word failed")
          end

          y_bn = horner(coeffs, x_bn, prime, ctx)
          bns_to_free << y_bn

          # Pad both coordinates to the prime's byte length, matching
          # Clevis's `[xx || yy]` layout for interoperability.
          coord_len = prime_byte_size(prime)
          x_bytes = bn_to_padded_bytes(x_bn, coord_len)
          y_bytes = bn_to_padded_bytes(y_bn, coord_len)
          points << Point.new(x_bytes, y_bytes)
        end

        prime_bytes = bn_to_padded_bytes(prime, prime_byte_size(prime))
        SplitResult.new(prime: prime_bytes, threshold: threshold, points: points)
      ensure
        bns_to_free.each { |b| LibCrypto.bn_free(b) }
        LibCrypto.bn_ctx_free(ctx)
      end
    end

    # Reconstruct the secret from `points` (>= threshold of them) and
    # the same `prime` that was used to split. Returns `secret_size`
    # bytes. Lagrange interpolation at X = 0 in GF(p).
    def recover(prime : Bytes, points : Array(Point), secret_size : Int32) : Bytes
      raise Error.new("at least 1 point is required") if points.empty?
      # Detect duplicate x-values (would make Lagrange undefined).
      xs = points.map(&.x)
      raise Error.new("duplicate x-values") if xs.uniq.size != xs.size

      ctx = LibCrypto.bn_ctx_new
      raise Error.new("BN_CTX_new failed") if ctx.null?
      bns_to_free = [] of LibCrypto::Bignum

      begin
        prime_bn = bn_from_bytes(prime)
        bns_to_free << prime_bn

        result = LibCrypto.bn_new
        bns_to_free << result
        if LibCrypto.bn_set_word(result, 0_u64) != 1
          raise Error.new("BN_set_word(0) failed")
        end

        bn_points = points.map do |pt|
          x = bn_from_bytes(pt.x); bns_to_free << x
          y = bn_from_bytes(pt.y); bns_to_free << y
          {x, y}
        end

        bn_points.each_with_index do |(x_i, y_i), i|
          # Lagrange basis L_i(0) = prod_{j != i} (-x_j) / (x_i - x_j) mod p
          numerator = LibCrypto.bn_new
          bns_to_free << numerator
          if LibCrypto.bn_set_word(numerator, 1_u64) != 1
            raise Error.new("BN_set_word(num=1) failed")
          end
          denominator = LibCrypto.bn_new
          bns_to_free << denominator
          if LibCrypto.bn_set_word(denominator, 1_u64) != 1
            raise Error.new("BN_set_word(den=1) failed")
          end

          zero_bn = LibCrypto.bn_new
          bns_to_free << zero_bn
          if LibCrypto.bn_set_word(zero_bn, 0_u64) != 1
            raise Error.new("BN_set_word(0) failed")
          end

          bn_points.each_with_index do |(x_j, _), j|
            next if i == j

            # numerator *= (0 - x_j) mod p
            neg_xj = LibCrypto.bn_new
            bns_to_free << neg_xj
            if LibCrypto.bn_mod_sub(neg_xj, zero_bn, x_j, prime_bn, ctx) != 1
              raise Error.new("BN_mod_sub failed")
            end
            new_num = LibCrypto.bn_new
            bns_to_free << new_num
            if LibCrypto.bn_mod_mul(new_num, numerator, neg_xj, prime_bn, ctx) != 1
              raise Error.new("BN_mod_mul num failed")
            end
            numerator = new_num

            # denominator *= (x_i - x_j) mod p
            diff = LibCrypto.bn_new
            bns_to_free << diff
            if LibCrypto.bn_mod_sub(diff, x_i, x_j, prime_bn, ctx) != 1
              raise Error.new("BN_mod_sub diff failed")
            end
            new_den = LibCrypto.bn_new
            bns_to_free << new_den
            if LibCrypto.bn_mod_mul(new_den, denominator, diff, prime_bn, ctx) != 1
              raise Error.new("BN_mod_mul den failed")
            end
            denominator = new_den
          end

          # term = y_i * numerator * inverse(denominator) mod p
          inv = LibCrypto.bn_new
          bns_to_free << inv
          if LibCrypto.bn_mod_inverse(inv, denominator, prime_bn, ctx).null?
            raise Error.new("BN_mod_inverse failed (denominator not coprime to p?)")
          end

          tmp = LibCrypto.bn_new
          bns_to_free << tmp
          if LibCrypto.bn_mod_mul(tmp, y_i, numerator, prime_bn, ctx) != 1
            raise Error.new("BN_mod_mul y*num failed")
          end
          term = LibCrypto.bn_new
          bns_to_free << term
          if LibCrypto.bn_mod_mul(term, tmp, inv, prime_bn, ctx) != 1
            raise Error.new("BN_mod_mul term failed")
          end

          new_result = LibCrypto.bn_new
          bns_to_free << new_result
          if LibCrypto.bn_mod_add(new_result, result, term, prime_bn, ctx) != 1
            raise Error.new("BN_mod_add failed")
          end
          result = new_result
        end

        bn_to_padded_bytes(result, secret_size)
      ensure
        bns_to_free.each { |b| LibCrypto.bn_free(b) }
        LibCrypto.bn_ctx_free(ctx)
      end
    end

    # Horner's method to evaluate polynomial f(x) = a₀ + a₁·x + … + a_{n-1}·x^{n-1}
    # mod p. Caller owns the returned BIGNUM.
    private def horner(coeffs : Array(LibCrypto::Bignum), x : LibCrypto::Bignum,
                       prime : LibCrypto::Bignum, ctx : LibCrypto::BignumCtx) : LibCrypto::Bignum
      result = LibCrypto.bn_new
      if LibCrypto.bn_set_word(result, 0_u64) != 1
        raise Error.new("BN_set_word failed in horner")
      end
      coeffs.reverse_each do |c|
        # result = result * x + c (mod p)
        tmp = LibCrypto.bn_new
        if LibCrypto.bn_mod_mul(tmp, result, x, prime, ctx) != 1
          LibCrypto.bn_free(tmp)
          raise Error.new("BN_mod_mul failed in horner")
        end
        new_result = LibCrypto.bn_new
        if LibCrypto.bn_mod_add(new_result, tmp, c, prime, ctx) != 1
          LibCrypto.bn_free(new_result)
          LibCrypto.bn_free(tmp)
          raise Error.new("BN_mod_add failed in horner")
        end
        LibCrypto.bn_free(tmp)
        LibCrypto.bn_free(result)
        result = new_result
      end
      result
    end

    private def bn_from_bytes(bytes : Bytes) : LibCrypto::Bignum
      bn = LibCrypto.bn_bin2bn(bytes.to_unsafe, bytes.size, Pointer(Void).null.as(LibCrypto::Bignum))
      raise Error.new("BN_bin2bn failed") if bn.null?
      bn
    end

    private def bn_to_padded_bytes(bn : LibCrypto::Bignum, target_len : Int32) : Bytes
      result = Bytes.new(target_len)
      written = LibCrypto.bn_bn2binpad(bn, result.to_unsafe, target_len)
      raise Error.new("BN_bn2binpad failed (got #{written}, expected #{target_len})") if written != target_len
      result
    end

    private def prime_byte_size(prime : LibCrypto::Bignum) : Int32
      bits = LibCrypto.bn_num_bits(prime)
      (bits + 7) // 8
    end
  end
end
