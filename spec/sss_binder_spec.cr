require "./spec_helper"

describe ClevisZfs::SssBinder do
  describe "round-trip via MockTangClient (no network)" do
    it "binds with K=2/N=3 and recovers with any 2 of 3 Tangs" do
      MOCK_TANG_REGISTRY.clear
      tangs = [
        MockTangClient.new("http://tang-1.example"),
        MockTangClient.new("http://tang-2.example"),
        MockTangClient.new("http://tang-3.example"),
      ]
      payload = "Tang SSS round-trip with threshold 2/3"

      jwe = ClevisZfs::SssBinder.bind(payload, tangs, threshold: 2)
      jwe.split('.').size.should eq(5)

      recovered = ClevisZfs::SssBinder.recover(jwe, &mock_tang_factory)
      String.new(recovered).should eq(payload)
    end

    it "still recovers when 1 Tang is unreachable (K=2/N=3)" do
      MOCK_TANG_REGISTRY.clear
      tangs = [
        MockTangClient.new("http://tang-1.example"),
        MockTangClient.new("http://tang-2.example"),
        MockTangClient.new("http://tang-3.example"),
      ] of ClevisZfs::TangClient

      payload = "tolerates 1 panne sur 3"
      jwe = ClevisZfs::SssBinder.bind(payload, tangs, threshold: 2)

      # Simulate tang-2 going offline by removing it from the registry.
      MOCK_TANG_REGISTRY.delete("http://tang-2.example")

      recovered = ClevisZfs::SssBinder.recover(jwe, &mock_tang_factory)
      String.new(recovered).should eq(payload)
    end

    it "fails when too many Tangs are down (K=2/N=3, 2 down)" do
      MOCK_TANG_REGISTRY.clear
      tangs = [
        MockTangClient.new("http://tang-1.example"),
        MockTangClient.new("http://tang-2.example"),
        MockTangClient.new("http://tang-3.example"),
      ] of ClevisZfs::TangClient

      jwe = ClevisZfs::SssBinder.bind("should fail", tangs, threshold: 2)

      MOCK_TANG_REGISTRY.delete("http://tang-1.example")
      MOCK_TANG_REGISTRY.delete("http://tang-2.example")

      expect_raises(ClevisZfs::SssBinder::Error, /shares/) do
        ClevisZfs::SssBinder.recover(jwe, &mock_tang_factory)
      end
    end

    it "round-trips K=N=3 (all required, no panne tolerated)" do
      MOCK_TANG_REGISTRY.clear
      tangs = [
        MockTangClient.new("http://t1"),
        MockTangClient.new("http://t2"),
        MockTangClient.new("http://t3"),
      ]
      jwe = ClevisZfs::SssBinder.bind("strict", tangs, threshold: 3)
      recovered = ClevisZfs::SssBinder.recover(jwe, &mock_tang_factory)
      String.new(recovered).should eq("strict")
    end

    it "round-trips K=1/N=1 (degenerate, equivalent to plain TangClient)" do
      MOCK_TANG_REGISTRY.clear
      tangs = [MockTangClient.new("http://t1")]
      jwe = ClevisZfs::SssBinder.bind("solo", tangs, threshold: 1)
      recovered = ClevisZfs::SssBinder.recover(jwe, &mock_tang_factory)
      String.new(recovered).should eq("solo")
    end

    it "round-trips a 64-byte GELI keyfile" do
      MOCK_TANG_REGISTRY.clear
      tangs = [
        MockTangClient.new("http://a"),
        MockTangClient.new("http://b"),
        MockTangClient.new("http://c"),
      ]
      keyfile = ClevisZfs::Zfs.random_key_hex.to_slice
      jwe = ClevisZfs::SssBinder.bind(keyfile, tangs, threshold: 2)
      recovered = ClevisZfs::SssBinder.recover(jwe, &mock_tang_factory)
      recovered.should eq(keyfile)
    end
  end

  describe "is_sss?" do
    it "detects SSS-flavored JWEs" do
      MOCK_TANG_REGISTRY.clear
      tangs = [MockTangClient.new("http://x"), MockTangClient.new("http://y")]
      jwe = ClevisZfs::SssBinder.bind("payload", tangs, threshold: 1)
      ClevisZfs::SssBinder.is_sss?(jwe).should be_true
    end

    it "returns false for a plain Tang JWE (no SSS)" do
      MOCK_TANG_REGISTRY.clear
      tang = MockTangClient.new("http://solo")
      jwe = tang.bind("payload")
      ClevisZfs::SssBinder.is_sss?(jwe).should be_false
    end

    it "returns false for malformed JWEs" do
      ClevisZfs::SssBinder.is_sss?("not.a.jwe").should be_false
    end
  end

  describe "validation" do
    it "rejects threshold > number of Tangs" do
      MOCK_TANG_REGISTRY.clear
      tangs = [MockTangClient.new("http://a")]
      expect_raises(ClevisZfs::SssBinder::Error, /threshold/) do
        ClevisZfs::SssBinder.bind("p", tangs, threshold: 2)
      end
    end

    it "rejects an empty Tang list" do
      empty = [] of ClevisZfs::TangClient
      expect_raises(ClevisZfs::SssBinder::Error, /required/) do
        ClevisZfs::SssBinder.bind("p", empty, threshold: 1)
      end
    end
  end
end
