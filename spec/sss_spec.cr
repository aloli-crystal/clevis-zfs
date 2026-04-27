require "./spec_helper"

describe CrystalClevisZfs::Sss do
  describe "round-trip" do
    it "splits and recovers a 32-byte secret with K=2/N=3" do
      secret = Random::Secure.random_bytes(32)
      result = CrystalClevisZfs::Sss.split(secret, threshold: 2, count: 3)
      result.points.size.should eq(3)
      result.threshold.should eq(2)

      # Any K of N points reconstructs the secret.
      [
        [result.points[0], result.points[1]],
        [result.points[0], result.points[2]],
        [result.points[1], result.points[2]],
      ].each do |subset|
        recovered = CrystalClevisZfs::Sss.recover(result.prime, subset, secret_size: 32)
        recovered.should eq(secret)
      end
    end

    it "rejects K-1 points" do
      secret = Random::Secure.random_bytes(32)
      result = CrystalClevisZfs::Sss.split(secret, threshold: 3, count: 5)

      # With only 2 of 3 required, the recovered value is statistically
      # different from the secret (we don't enforce an error, but the
      # value should not match).
      partial = result.points[0, 2]
      recovered = CrystalClevisZfs::Sss.recover(result.prime, partial, secret_size: 32)
      recovered.should_not eq(secret)
    end

    it "round-trips K=1/N=1 (degenerate, equivalent to no sharing)" do
      secret = Random::Secure.random_bytes(32)
      result = CrystalClevisZfs::Sss.split(secret, threshold: 1, count: 1)
      result.points.size.should eq(1)
      recovered = CrystalClevisZfs::Sss.recover(result.prime, result.points, secret_size: 32)
      recovered.should eq(secret)
    end

    it "round-trips K=N=3 (all required)" do
      secret = Random::Secure.random_bytes(32)
      result = CrystalClevisZfs::Sss.split(secret, threshold: 3, count: 3)
      recovered = CrystalClevisZfs::Sss.recover(result.prime, result.points, secret_size: 32)
      recovered.should eq(secret)
    end

    it "round-trips K=3/N=5" do
      secret = Random::Secure.random_bytes(32)
      result = CrystalClevisZfs::Sss.split(secret, threshold: 3, count: 5)
      [
        [0, 1, 2],
        [0, 2, 4],
        [1, 3, 4],
        [2, 3, 4],
      ].each do |idxs|
        subset = idxs.map { |i| result.points[i] }
        recovered = CrystalClevisZfs::Sss.recover(result.prime, subset, secret_size: 32)
        recovered.should eq(secret)
      end
    end

    it "is deterministic given the same prime + points" do
      secret = Random::Secure.random_bytes(32)
      result = CrystalClevisZfs::Sss.split(secret, threshold: 2, count: 3)
      r1 = CrystalClevisZfs::Sss.recover(result.prime, result.points[0, 2], secret_size: 32)
      r2 = CrystalClevisZfs::Sss.recover(result.prime, result.points[0, 2], secret_size: 32)
      r1.should eq(r2)
    end

    it "produces different points across two splits of the same secret" do
      secret = Random::Secure.random_bytes(32)
      a = CrystalClevisZfs::Sss.split(secret, threshold: 2, count: 3)
      b = CrystalClevisZfs::Sss.split(secret, threshold: 2, count: 3)
      a.points[0].y.should_not eq(b.points[0].y)
      # But both round-trip to the same secret.
      ra = CrystalClevisZfs::Sss.recover(a.prime, a.points[0, 2], secret_size: 32)
      rb = CrystalClevisZfs::Sss.recover(b.prime, b.points[0, 2], secret_size: 32)
      ra.should eq(secret)
      rb.should eq(secret)
    end

    it "round-trips a 16-byte secret with K=2/N=3" do
      secret = Random::Secure.random_bytes(16)
      result = CrystalClevisZfs::Sss.split(secret, threshold: 2, count: 3)
      recovered = CrystalClevisZfs::Sss.recover(result.prime, result.points[0, 2], secret_size: 16)
      recovered.should eq(secret)
    end
  end

  describe "validation" do
    it "rejects threshold < 1" do
      expect_raises(CrystalClevisZfs::Sss::Error, /threshold/) do
        CrystalClevisZfs::Sss.split("x".to_slice, threshold: 0, count: 1)
      end
    end

    it "rejects count < threshold" do
      expect_raises(CrystalClevisZfs::Sss::Error, /count/) do
        CrystalClevisZfs::Sss.split("x".to_slice, threshold: 3, count: 2)
      end
    end

    it "rejects duplicate x-values at recover time" do
      secret = Random::Secure.random_bytes(32)
      result = CrystalClevisZfs::Sss.split(secret, threshold: 2, count: 3)
      bad = [result.points[0], result.points[0]]
      expect_raises(CrystalClevisZfs::Sss::Error, /duplicate/) do
        CrystalClevisZfs::Sss.recover(result.prime, bad, secret_size: 32)
      end
    end
  end
end
