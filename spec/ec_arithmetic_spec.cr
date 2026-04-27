require "./spec_helper"

describe CrystalClevisZfs::ECArithmetic do
  describe "scalar_mul" do
    it "matches the standard ECDH derivation (X-coordinate)" do
      a = CrystalJose::JWK::ECKey.generate(CrystalJose::JWK::Curve::P256)
      b = CrystalJose::JWK::ECKey.generate(CrystalJose::JWK::Curve::P256)

      ab_point = CrystalClevisZfs::ECArithmetic.scalar_mul(a, b.public_key)
      ba_point = CrystalClevisZfs::ECArithmetic.scalar_mul(b, a.public_key)

      ab_point.x.should eq(ba_point.x)
      ab_point.x.should eq(CrystalJose::JWE.ecdh_derive(a, b.public_key))
    end
  end

  describe "Tang dance identity (P-256)" do
    it "satisfies (C+E).s == c.S + e.S" do
      # Tang server keypair
      s_priv = CrystalJose::JWK::ECKey.generate(CrystalJose::JWK::Curve::P256)
      # Client encryption ephemeral
      c_priv = CrystalJose::JWK::ECKey.generate(CrystalJose::JWK::Curve::P256)
      # Client recovery ephemeral
      e_priv = CrystalJose::JWK::ECKey.generate(CrystalJose::JWK::Curve::P256)

      # X = C + E
      x_pub = CrystalClevisZfs::ECArithmetic.add(c_priv.public_key, e_priv.public_key)
      # Y = s.X (server side)
      y_pub = CrystalClevisZfs::ECArithmetic.scalar_mul(s_priv, x_pub)

      # K_point = Y - e.S = s.C  (this is the original ECDH product)
      e_s = CrystalClevisZfs::ECArithmetic.scalar_mul(e_priv, s_priv.public_key)
      k_point = CrystalClevisZfs::ECArithmetic.subtract(y_pub, e_s)

      # Direct computation of s.C
      direct_sc = CrystalClevisZfs::ECArithmetic.scalar_mul(s_priv, c_priv.public_key)
      k_point.x.should eq(direct_sc.x)
      k_point.y.should eq(direct_sc.y)

      # And it equals the X-coordinate of the original c.S
      direct_cs = CrystalClevisZfs::ECArithmetic.scalar_mul(c_priv, s_priv.public_key)
      k_point.x.should eq(direct_cs.x)
    end

    it "satisfies the dance on P-521 too" do
      s_priv = CrystalJose::JWK::ECKey.generate(CrystalJose::JWK::Curve::P521)
      c_priv = CrystalJose::JWK::ECKey.generate(CrystalJose::JWK::Curve::P521)
      e_priv = CrystalJose::JWK::ECKey.generate(CrystalJose::JWK::Curve::P521)

      x_pub = CrystalClevisZfs::ECArithmetic.add(c_priv.public_key, e_priv.public_key)
      y_pub = CrystalClevisZfs::ECArithmetic.scalar_mul(s_priv, x_pub)
      e_s = CrystalClevisZfs::ECArithmetic.scalar_mul(e_priv, s_priv.public_key)
      k_point = CrystalClevisZfs::ECArithmetic.subtract(y_pub, e_s)

      direct_cs = CrystalClevisZfs::ECArithmetic.scalar_mul(c_priv, s_priv.public_key)
      k_point.x.should eq(direct_cs.x)
    end
  end

  describe "subtract" do
    it "is the inverse of add" do
      a = CrystalJose::JWK::ECKey.generate(CrystalJose::JWK::Curve::P256)
      b = CrystalJose::JWK::ECKey.generate(CrystalJose::JWK::Curve::P256)

      sum = CrystalClevisZfs::ECArithmetic.add(a.public_key, b.public_key)
      back = CrystalClevisZfs::ECArithmetic.subtract(sum, b.public_key)

      back.x.should eq(a.x)
      back.y.should eq(a.y)
    end
  end

  describe "curve mismatch" do
    it "rejects mixed curves on add" do
      a = CrystalJose::JWK::ECKey.generate(CrystalJose::JWK::Curve::P256)
      b = CrystalJose::JWK::ECKey.generate(CrystalJose::JWK::Curve::P521)
      expect_raises(CrystalClevisZfs::ECArithmetic::Error, /curve/) do
        CrystalClevisZfs::ECArithmetic.add(a.public_key, b.public_key)
      end
    end
  end
end
