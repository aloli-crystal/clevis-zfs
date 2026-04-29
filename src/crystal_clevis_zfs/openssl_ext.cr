require "openssl/lib_crypto"
require "jose"

# Additional LibCrypto bindings for EC point arithmetic, needed by
# the Tang client recovery dance (point addition, scalar
# multiplication, negation). Builds on `CrystalJose`'s bindings.
lib LibCrypto
  fun ec_point_add = EC_POINT_add(group : EcGroup, r : EcPoint, a : EcPoint, b : EcPoint, ctx : BignumCtx) : Int
  fun ec_point_invert = EC_POINT_invert(group : EcGroup, point : EcPoint, ctx : BignumCtx) : Int
  fun ec_point_mul = EC_POINT_mul(group : EcGroup, r : EcPoint, n : Bignum, q : EcPoint, m : Bignum, ctx : BignumCtx) : Int
  fun ec_point_dup = EC_POINT_dup(src : EcPoint, group : EcGroup) : EcPoint
  fun ec_point_is_at_infinity = EC_POINT_is_at_infinity(group : EcGroup, point : EcPoint) : Int

  # Bignum arithmetic in GF(p), used by Shamir Secret Sharing.
  fun bn_generate_prime_ex = BN_generate_prime_ex(ret : Bignum, bits : Int, safe : Int, add : Bignum, rem : Bignum, cb : Void*) : Int
  fun bn_rand_range = BN_rand_range(rnd : Bignum, range : Bignum) : Int
  fun bn_mod_add = BN_mod_add(r : Bignum, a : Bignum, b : Bignum, m : Bignum, ctx : BignumCtx) : Int
  fun bn_mod_sub = BN_mod_sub(r : Bignum, a : Bignum, b : Bignum, m : Bignum, ctx : BignumCtx) : Int
  fun bn_mod_mul = BN_mod_mul(r : Bignum, a : Bignum, b : Bignum, m : Bignum, ctx : BignumCtx) : Int
  fun bn_mod_exp = BN_mod_exp(r : Bignum, a : Bignum, p : Bignum, m : Bignum, ctx : BignumCtx) : Int
  fun bn_mod_inverse = BN_mod_inverse(r : Bignum, a : Bignum, n : Bignum, ctx : BignumCtx) : Bignum
  fun bn_set_word = BN_set_word(a : Bignum, w : ULong) : Int
  fun bn_num_bytes_macro = BN_num_bytes(a : Bignum) : Int
  fun bn_cmp = BN_cmp(a : Bignum, b : Bignum) : Int
  fun bn_is_zero = BN_is_zero(a : Bignum) : Int
end
