require "./spec_helper"

describe ClevisZfs::ECArithmetic do
  describe "scalar_mul" do
    it "matches the standard ECDH derivation (X-coordinate)" do
      a = Jose::JWK::ECKey.generate(Jose::JWK::Curve::P256)
      b = Jose::JWK::ECKey.generate(Jose::JWK::Curve::P256)

      ab_point = ClevisZfs::ECArithmetic.scalar_mul(a, b.public_key)
      ba_point = ClevisZfs::ECArithmetic.scalar_mul(b, a.public_key)

      ab_point.x.should eq(ba_point.x)
      ab_point.x.should eq(Jose::JWE.ecdh_derive(a, b.public_key))
    end
  end

  describe "Tang dance identity (P-256)" do
    it "satisfies (C+E).s == c.S + e.S" do
      # Tang server keypair
      s_priv = Jose::JWK::ECKey.generate(Jose::JWK::Curve::P256)
      # Client encryption ephemeral
      c_priv = Jose::JWK::ECKey.generate(Jose::JWK::Curve::P256)
      # Client recovery ephemeral
      e_priv = Jose::JWK::ECKey.generate(Jose::JWK::Curve::P256)

      # X = C + E
      x_pub = ClevisZfs::ECArithmetic.add(c_priv.public_key, e_priv.public_key)
      # Y = s.X (server side)
      y_pub = ClevisZfs::ECArithmetic.scalar_mul(s_priv, x_pub)

      # K_point = Y - e.S = s.C  (this is the original ECDH product)
      e_s = ClevisZfs::ECArithmetic.scalar_mul(e_priv, s_priv.public_key)
      k_point = ClevisZfs::ECArithmetic.subtract(y_pub, e_s)

      # Direct computation of s.C
      direct_sc = ClevisZfs::ECArithmetic.scalar_mul(s_priv, c_priv.public_key)
      k_point.x.should eq(direct_sc.x)
      k_point.y.should eq(direct_sc.y)

      # And it equals the X-coordinate of the original c.S
      direct_cs = ClevisZfs::ECArithmetic.scalar_mul(c_priv, s_priv.public_key)
      k_point.x.should eq(direct_cs.x)
    end

    it "satisfies the dance on P-521 too" do
      s_priv = Jose::JWK::ECKey.generate(Jose::JWK::Curve::P521)
      c_priv = Jose::JWK::ECKey.generate(Jose::JWK::Curve::P521)
      e_priv = Jose::JWK::ECKey.generate(Jose::JWK::Curve::P521)

      x_pub = ClevisZfs::ECArithmetic.add(c_priv.public_key, e_priv.public_key)
      y_pub = ClevisZfs::ECArithmetic.scalar_mul(s_priv, x_pub)
      e_s = ClevisZfs::ECArithmetic.scalar_mul(e_priv, s_priv.public_key)
      k_point = ClevisZfs::ECArithmetic.subtract(y_pub, e_s)

      direct_cs = ClevisZfs::ECArithmetic.scalar_mul(c_priv, s_priv.public_key)
      k_point.x.should eq(direct_cs.x)
    end
  end

  describe "subtract" do
    it "is the inverse of add" do
      a = Jose::JWK::ECKey.generate(Jose::JWK::Curve::P256)
      b = Jose::JWK::ECKey.generate(Jose::JWK::Curve::P256)

      sum = ClevisZfs::ECArithmetic.add(a.public_key, b.public_key)
      back = ClevisZfs::ECArithmetic.subtract(sum, b.public_key)

      back.x.should eq(a.x)
      back.y.should eq(a.y)
    end
  end

  describe "curve mismatch" do
    it "rejects mixed curves on add" do
      a = Jose::JWK::ECKey.generate(Jose::JWK::Curve::P256)
      b = Jose::JWK::ECKey.generate(Jose::JWK::Curve::P521)
      expect_raises(ClevisZfs::ECArithmetic::Error, /curve/) do
        ClevisZfs::ECArithmetic.add(a.public_key, b.public_key)
      end
    end
  end
end
