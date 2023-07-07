require "./spec_helper"

describe "XmlSecurity" do
  @base64cert : String?
  @document : XMLSecurity::SignedDocument?

  let(:decoded_response) { Base64.decode_string(response_document_without_recipient) }
  let(:document) { XMLSecurity::SignedDocument.new(decoded_response) }
  let(:settings) { Saml::Settings.new }

  before do
    @base64cert = document.xpath_node("//ds:X509Certificate", {"ds" => XMLSecurity::BaseDocument::DSIG}).try(&.text)
  end

  describe "StarfieldTMS" do
    def response
      r = Saml::Response.new(fixture(:starfield_response))
      r.settings = Saml::Settings.new({:idp_cert_fingerprint => "8D:BA:53:8E:A3:B6:F9:F1:69:6C:BB:D9:D8:BD:41:B3:AC:4F:9D:4D"})
      r
    end

    # it "be able to validate a good response" do
    #   Timecop.travel( Time.parse_rfc3339("2012-11-28 17:55:00Z") ) do
    #     r = Saml::Response.new(
    #       fixture(:starfield_response),
    #       {:skip_subject_confirmation => true.as(Saml::Response::OptionValue)}
    #     )
    #     r.settings = Saml::Settings.new({:idp_cert_fingerprint => "8D:BA:53:8E:A3:B6:F9:F1:69:6C:BB:D9:D8:BD:41:B3:AC:4F:9D:4D"})
    #     r.is_valid?
    #     puts "ERRORS #{r.errors.inspect}"
    #     assert r.is_valid?
    #   end
    # end

    it "fail before response is valid" do
      Timecop.travel( Time.parse_rfc3339("2012-11-20 17:55:00Z") ) do
        r = response
        assert !r.is_valid?

        time_1 = "2012-11-20 17:55:00 UTC < 2012-11-28 17:53:45 UTC"
        time_2 = "Tue Nov 20 17:55:00 UTC 2012 < Wed Nov 28 17:53:45 UTC 2012"

        errors = [time_1, time_2].map do |time|
          "Current time is earlier than NotBefore condition (#{time} - 0s)"
        end

        assert((r.errors & errors).any?)
      end
    end

    # it "fail after response expires" do
    #   Timecop.travel( Time.parse_rfc3339("2012-11-30 17:55:00Z") ) do
    #     assert !response.is_valid?

    #     contains_expected_error = response.errors.includes?("Current time is on or after NotOnOrAfter condition (2012-11-30 17:55:00 UTC >= 2012-11-28 18:33:45 UTC + 1s)")
    #     contains_expected_error ||= response.errors.includes?("Current time is on or after NotOnOrAfter condition (Fri Nov 30 17:55:00 UTC 2012 >= Wed Nov 28 18:33:45 UTC 2012 + 1s)")
    #     assert contains_expected_error
    #   end
    # end
  end
end