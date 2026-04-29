require "spec"
require "../src/clevis-zfs"

# In-memory registry of MockTangClient instances keyed by URL. Tests
# can use `MOCK_TANG_REGISTRY[url]` (or the `mock_tang_factory` proc
# below) when they need SssBinder to round-trip through the mocks.
MOCK_TANG_REGISTRY = {} of String => CrystalClevisZfs::TangClient

def mock_tang_factory : Proc(String, CrystalClevisZfs::TangClient)
  ->(url : String) {
    MOCK_TANG_REGISTRY[url]? || raise "no mock registered for #{url}"
  }
end

# A self-contained Tang server simulation: hosts its own keypairs,
# produces a signed advertisement, and answers `recover` requests
# with the correct EC point multiplication. Used to drive the full
# bind/recover round-trip without a live network.
class MockTangClient < CrystalClevisZfs::TangClient
  getter signing_priv : CrystalJose::JWK::ECKey
  getter derive_priv : CrystalJose::JWK::ECKey

  def initialize(url : String,
                 @signing_priv : CrystalJose::JWK::ECKey = CrystalJose::JWK::ECKey.generate(CrystalJose::JWK::Curve::P521),
                 @derive_priv : CrystalJose::JWK::ECKey = CrystalJose::JWK::ECKey.generate(CrystalJose::JWK::Curve::P521))
    super(url)
    MOCK_TANG_REGISTRY[url] = self
  end

  protected def fetch_advertisement : CrystalClevisZfs::Advertisement
    payload = build_jwks
    jws = sign_advertisement(payload)
    CrystalClevisZfs::Advertisement.from_jws(jws)
  end

  protected def post_recover(kid : String, x_point : CrystalJose::JWK::ECKey) : CrystalJose::JWK::ECKey
    raise "wrong kid" unless kid == @derive_priv.thumbprint_base64url
    # Y = derive_priv.d * x_point
    CrystalClevisZfs::ECArithmetic.scalar_mul(@derive_priv, x_point)
  end

  private def build_jwks : String
    sig_pub = @signing_priv.public_key.to_jwk_hash
    sig_pub["use"] = "sig"
    sig_pub["key_ops"] = "VERIFY_PLACEHOLDER"

    derive_pub = @derive_priv.public_key.to_jwk_hash
    derive_pub["use"] = "deriveKey"
    derive_pub["key_ops"] = "DERIVEKEY_PLACEHOLDER"

    sig_json = sig_pub.to_json.sub(%("VERIFY_PLACEHOLDER"), %(["verify"]))
    derive_json = derive_pub.to_json.sub(%("DERIVEKEY_PLACEHOLDER"), %(["deriveKey"]))

    %({"keys":[#{sig_json},#{derive_json}]})
  end

  private def sign_advertisement(payload : String) : String
    alg = case @signing_priv.curve
          in .p256? then CrystalJose::JWS::Algorithm::ES256
          in .p384? then CrystalJose::JWS::Algorithm::ES384
          in .p521? then CrystalJose::JWS::Algorithm::ES512
          end
    CrystalJose::JWS.sign(payload, alg, @signing_priv)
  end
end
