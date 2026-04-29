require "./spec_helper"

describe ClevisZfs::TangClient do
  describe "bind / recover round-trip with a mock server" do
    it "round-trips a small payload (P-521)" do
      tang = MockTangClient.new("http://mock-tang.example.com")
      payload = "the GELI keyfile would go here"
      jwe = tang.bind(payload)
      decrypted = tang.recover(jwe)
      String.new(decrypted).should eq(payload)
    end

    it "round-trips a P-256 deriveKey" do
      sig_priv = Jose::JWK::ECKey.generate(Jose::JWK::Curve::P256)
      derive_priv = Jose::JWK::ECKey.generate(Jose::JWK::Curve::P256)
      tang = MockTangClient.new("http://mock", sig_priv, derive_priv)

      payload = "P-256 round-trip"
      jwe = tang.bind(payload)
      decrypted = tang.recover(jwe)
      String.new(decrypted).should eq(payload)
    end

    it "round-trips a 64-byte random keyfile (typical GELI key)" do
      tang = MockTangClient.new("http://mock")
      keyfile = ClevisZfs::Zfs.random_key_hex.to_slice
      jwe = tang.bind(keyfile)
      decrypted = tang.recover(jwe)
      decrypted.should eq(keyfile)
    end

    it "produces a JWE with 5 compact parts and proper claims" do
      tang = MockTangClient.new("http://example.com/tang")
      jwe = tang.bind("hi")
      jwe.split('.').size.should eq(5)

      header_b64 = jwe.split('.').first
      header = Hash(String, JSON::Any).from_json(String.new(Jose::Utils.base64url_decode(header_b64)))
      header["alg"].as_s.should eq("ECDH-ES")
      header["enc"].as_s.should eq("A256GCM")
      header["epk"].should_not be_nil
      header["kid"].as_s.should eq(tang.derive_priv.thumbprint_base64url)
      header["clevis"].as_h["pin"].as_s.should eq("tang")
      header["clevis"].as_h["tang"].as_h["url"].as_s.should eq("http://example.com/tang")
    end
  end

  describe "advertisement validation" do
    it "rejects an advertisement signed by a key that is not in the JWKSet" do
      foreign_signer = Jose::JWK::ECKey.generate(Jose::JWK::Curve::P256)
      embedded_signer = Jose::JWK::ECKey.generate(Jose::JWK::Curve::P256)
      derive_key = Jose::JWK::ECKey.generate(Jose::JWK::Curve::P256)

      embedded_pub = embedded_signer.public_key.to_jwk_hash
      embedded_pub["use"] = "sig"
      derive_pub = derive_key.public_key.to_jwk_hash
      derive_pub["use"] = "deriveKey"

      payload = %({"keys":[#{embedded_pub.to_json},#{derive_pub.to_json}]})
      jws = Jose::JWS.sign(payload, Jose::JWS::Algorithm::ES256, foreign_signer)

      expect_raises(ClevisZfs::Advertisement::Error, /signature/) do
        ClevisZfs::Advertisement.from_jws(jws)
      end
    end

    it "accepts a properly self-signed advertisement" do
      tang = MockTangClient.new("http://mock")
      adv = tang.advertisement
      adv.derive_keys.size.should eq(1)
      adv.signing_keys.size.should eq(1)
    end
  end

  describe "recover error handling" do
    it "rejects a JWE referencing an unknown kid" do
      tang = MockTangClient.new("http://mock")
      jwe = tang.bind("plain")

      # Force the kid in the header to something Tang does not have.
      header_b64, enc_key, iv_b64, ct_b64, tag_b64 = jwe.split('.')
      header = Hash(String, JSON::Any).from_json(String.new(Jose::Utils.base64url_decode(header_b64)))
      header["kid"] = JSON::Any.new("bogus-thumbprint")
      bad_header_b64 = Jose::Utils.base64url_encode(header.to_json)
      tampered = "#{bad_header_b64}.#{enc_key}.#{iv_b64}.#{ct_b64}.#{tag_b64}"

      expect_raises(ClevisZfs::TangClient::Error, /not found/) do
        tang.recover(tampered)
      end
    end

    it "rejects an alg other than ECDH-ES" do
      tang = MockTangClient.new("http://mock")
      header = {"alg" => "RSA-OAEP", "enc" => "A256GCM"}
      header_b64 = Jose::Utils.base64url_encode(header.to_json)
      jwe = "#{header_b64}.x.x.x.x"
      expect_raises(ClevisZfs::TangClient::Error, /alg/) do
        tang.recover(jwe)
      end
    end
  end
end
