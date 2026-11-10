require "./spec_helper"

# Expose private validations to the specs.
class Saml::SloLogoutrequest
  def spec_send(method : Symbol) : Bool
    case method
    when :validate_id              then validate_id
    when :validate_version         then validate_version
    when :validate_not_on_or_after then validate_not_on_or_after
    when :validate_request_state   then validate_request_state
    when :validate_structure       then validate_structure
    when :validate_issuer          then validate_issuer
    when :validate_signature       then validate_signature
    else                                raise ArgumentError.new("unknown validation #{method}")
    end
  end
end

describe "SloLogoutrequest" do
  let(:settings) { Saml::Settings.new }
  let(:logout_request) { Saml::SloLogoutrequest.new(logout_request_document) }
  let(:invalid_logout_request) { Saml::SloLogoutrequest.new(invalid_logout_request_document) }

  def signature_options(params : Hash(String, String)) : Hash(Symbol, Saml::RedirectSignature::OptionValue)
    options = {} of Symbol => Saml::RedirectSignature::OptionValue
    options[:get_params] = params
    options
  end

  before do
    settings.idp_entity_id = "https://app.onelogin.com/saml/metadata/SOMEACCOUNT"
    settings.soft = true
    logout_request.settings = settings
    invalid_logout_request.settings = settings
  end

  describe "initiator" do
    it "raise an exception when logout request is initialized with nil" do
      assert_raises(ArgumentError) { Saml::SloLogoutrequest.new(nil) }
    end
  end

  describe "#is_valid?" do
    it "return false when logout request is initialized with blank data" do
      logout_request_blank = Saml::SloLogoutrequest.new("")
      assert !logout_request_blank.is_valid?
      assert_includes logout_request_blank.errors, "Blank logout request"
    end

    it "return true when the logout request is initialized with valid data" do
      assert logout_request.is_valid?
      assert_empty logout_request.errors
      assert_equal "someone@example.org", logout_request.nameid
    end

    it "should be idempotent when the logout request is initialized with invalid data" do
      assert !invalid_logout_request.is_valid?
      assert_equal ["Invalid SAML Logout Request. Not match the saml-schema-protocol-2.0.xsd"], invalid_logout_request.errors
      assert !invalid_logout_request.is_valid?
      assert_equal ["Invalid SAML Logout Request. Not match the saml-schema-protocol-2.0.xsd"], invalid_logout_request.errors
    end

    it "should be idempotent when the logout request is initialized with valid data" do
      assert logout_request.is_valid?
      assert_empty logout_request.errors
      assert logout_request.is_valid?
      assert_empty logout_request.errors
    end

    it "collect errors when collect_errors=true" do
      settings.idp_entity_id = "http://idp.example.com/invalid"
      settings.security[:logout_requests_signed] = true
      settings.certificate = crystal_saml_cert_text
      settings.private_key = crystal_saml_key_text
      settings.idp_cert = crystal_saml_cert_text
      settings.security[:signature_method] = XMLSecurity::Document::RSA_SHA1
      params = {} of String => String
      params["SAMLRequest"] = logout_request_deflated_base64
      params["RelayState"] = "http://invalid.example.com"
      params["Signature"] = "invalid_signature"
      params["SigAlg"] = XMLSecurity::Document::RSA_SHA1
      options = signature_options(params)

      logout_request_sign_test = Saml::SloLogoutrequest.new(params["SAMLRequest"], options)
      logout_request_sign_test.settings = settings

      collect_errors = true
      assert !logout_request_sign_test.is_valid?(collect_errors)
      assert_includes logout_request_sign_test.errors, "Invalid Signature on Logout Request"
      assert_includes logout_request_sign_test.errors, "Doesn't match the issuer, expected: <http://idp.example.com/invalid>, but was: <https://app.onelogin.com/saml/metadata/SOMEACCOUNT>"
    end

    it "raise error for invalid xml" do
      invalid_logout_request.soft = false
      assert_raises(Saml::ValidationError) { invalid_logout_request.is_valid? }
    end
  end

  describe "#nameid" do
    it "extract the value of the name id element" do
      assert_equal "someone@example.org", logout_request.nameid
    end
  end

  describe "#nameid_format" do
    let(:logout_request) { Saml::SloLogoutrequest.new(logout_request_document_with_name_id_format) }

    it "extract the format attribute of the name id element" do
      assert_equal "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", logout_request.nameid_format
    end
  end

  describe "#issuer" do
    it "return the issuer inside the logout request" do
      assert_equal "https://app.onelogin.com/saml/metadata/SOMEACCOUNT", logout_request.issuer
    end
  end

  describe "#id" do
    it "extract the value of the ID attribute" do
      assert_equal "_c0348950-935b-0131-1060-782bcb56fcaa", logout_request.id
    end
  end

  describe "#not_on_or_after" do
    it "extract the value of the NotOnOrAfter attribute" do
      time_value = "2014-07-17T01:01:48Z"
      assert_nil logout_request.not_on_or_after
      logout_request.document.root.not_nil!["NotOnOrAfter"] = time_value
      assert_equal Time.parse_rfc3339(time_value), logout_request.not_on_or_after
    end
  end

  describe "#session_indexes" do
    it "return empty array when no SessionIndex" do
      assert_equal [] of String, logout_request.session_indexes
    end

    it "return an Array with one SessionIndex" do
      logout_request_with_session_index = Saml::SloLogoutrequest.new(logout_request_xml_with_session_index)
      assert_equal ["_ea853497-c58a-408a-bc23-c849752d9741"], logout_request_with_session_index.session_indexes
    end
  end

  describe "#validate_id" do
    it "return true when there is a valid ID in the logout request" do
      assert logout_request.spec_send(:validate_id)
      assert_empty logout_request.errors
    end

    it "return false when there is an invalid ID in the logout request" do
      logout_request_blank = Saml::SloLogoutrequest.new("")
      assert !logout_request_blank.spec_send(:validate_id)
      assert_includes logout_request_blank.errors, "Missing ID attribute on Logout Request"
    end
  end

  describe "#validate_version" do
    it "return true when the logout request is SAML 2.0 Version" do
      assert logout_request.spec_send(:validate_version)
    end

    it "return false when the logout request is not SAML 2.0 Version" do
      logout_request_blank = Saml::SloLogoutrequest.new("")
      assert !logout_request_blank.spec_send(:validate_version)
      assert_includes logout_request_blank.errors, "Unsupported SAML version"
    end
  end

  describe "#validate_not_on_or_after" do
    it "return true when the logout request has a valid NotOnOrAfter or does not contain any" do
      assert logout_request.spec_send(:validate_not_on_or_after)
      assert_empty logout_request.errors

      Timecop.freeze Time.parse_rfc3339("2014-07-17T01:01:47Z") do
        logout_request.document.root.not_nil!["NotOnOrAfter"] = "2014-07-17T01:01:48Z"
        assert logout_request.spec_send(:validate_not_on_or_after)
        assert_empty logout_request.errors
      end
    end

    it "return false when the logout request has an invalid NotOnOrAfter" do
      Timecop.freeze Time.parse_rfc3339("2014-07-17T01:01:49Z") do
        logout_request.document.root.not_nil!["NotOnOrAfter"] = "2014-07-17T01:01:48Z"
        assert !logout_request.spec_send(:validate_not_on_or_after)
        assert_match(/Current time is on or after NotOnOrAfter/, logout_request.errors[0])
      end
    end

    it "raise when the logout request has an invalid NotOnOrAfter" do
      Timecop.freeze Time.parse_rfc3339("2014-07-17T01:01:49Z") do
        logout_request.document.root.not_nil!["NotOnOrAfter"] = "2014-07-17T01:01:48Z"
        logout_request.soft = false
        err = assert_raises(Saml::ValidationError) do
          logout_request.spec_send(:validate_not_on_or_after)
        end
        assert_includes err.message.to_s, "Current time is on or after NotOnOrAfter"
      end
    end

    it "optionally allows for clock drift" do
      logout_request.soft = true
      logout_request.document.root.not_nil!["NotOnOrAfter"] = "2011-06-14T18:31:01.516Z"

      # The NotBefore condition in the document is 2011-06-1418:31:01.516Z
      Timecop.freeze(Time.parse_rfc3339("2011-06-14T18:31:02Z")) do
        logout_request.options[:allowed_clock_drift] = 0.483
        assert !logout_request.spec_send(:validate_not_on_or_after)

        logout_request.options[:allowed_clock_drift] = 0.485
        assert logout_request.spec_send(:validate_not_on_or_after)

        logout_request.options[:allowed_clock_drift] = 0.485.seconds
        assert logout_request.spec_send(:validate_not_on_or_after)
      end
    end

    it "accepts a clock drift that exactly reaches the current time" do
      logout_request.document.root.not_nil!["NotOnOrAfter"] = "2011-06-14T18:31:01.516Z"

      Timecop.freeze(Time.parse_rfc3339("2011-06-14T18:31:02Z")) do
        logout_request.options[:allowed_clock_drift] = 0.484
        assert logout_request.spec_send(:validate_not_on_or_after)
      end
    end

    it "optionally allows for clock drift given as a string" do
      logout_request.document.root.not_nil!["NotOnOrAfter"] = "2011-06-14T18:31:01.516Z"

      Timecop.freeze(Time.parse_rfc3339("2011-06-14T18:31:02Z")) do
        logout_request.options[:allowed_clock_drift] = "0.483"
        assert !logout_request.spec_send(:validate_not_on_or_after)

        logout_request.options[:allowed_clock_drift] = "0.484"
        assert logout_request.spec_send(:validate_not_on_or_after)
      end
    end
  end

  describe "#validate_request_state" do
    it "return true when valid logout request xml" do
      assert logout_request.spec_send(:validate_request_state)
      assert_empty logout_request.errors
      assert logout_request.spec_send(:validate_request_state)
      assert_empty logout_request.errors
    end

    it "return false when invalid logout request xml" do
      logout_request_blank = Saml::SloLogoutrequest.new("")
      logout_request_blank.soft = true
      assert !logout_request_blank.spec_send(:validate_request_state)
      assert_includes logout_request_blank.errors, "Blank logout request"
    end

    it "raise error for invalid xml" do
      logout_request_blank = Saml::SloLogoutrequest.new("")
      logout_request_blank.soft = false
      err = assert_raises(Saml::ValidationError) do
        logout_request_blank.spec_send(:validate_request_state)
      end
      assert_includes err.message.to_s, "Blank logout request"
    end
  end

  describe "#validate_structure" do
    it "return true when encountering a valid Logout Request xml" do
      assert logout_request.spec_send(:validate_structure)
      assert_empty logout_request.errors
    end

    it "return false when encountering a Logout Request bad formatted" do
      assert !invalid_logout_request.spec_send(:validate_structure)
      assert_includes invalid_logout_request.errors, "Invalid SAML Logout Request. Not match the saml-schema-protocol-2.0.xsd"
    end

    it "raise when encountering a Logout Request bad formatted" do
      invalid_logout_request.soft = false
      err = assert_raises(Saml::ValidationError) do
        invalid_logout_request.spec_send(:validate_structure)
      end
      assert_includes err.message.to_s, "Element '{urn:oasis:names:tc:SAML:2.0:assertion}Issuer': This element is not expected"
    end
  end

  describe "#validate_issuer" do
    it "return true when the issuer of the Logout Request matchs the IdP entityId" do
      settings.idp_entity_id = "https://app.onelogin.com/saml/metadata/SOMEACCOUNT"
      assert logout_request.spec_send(:validate_issuer)
    end
    it "return false when the issuer of the Logout Request does not match the IdP entityId" do
      settings.idp_entity_id = "http://idp.example.com/invalid"
      assert !logout_request.spec_send(:validate_issuer)
      assert_includes logout_request.errors, "Doesn't match the issuer, expected: <#{settings.idp_entity_id}>, but was: <https://app.onelogin.com/saml/metadata/SOMEACCOUNT>"
    end
    it "raise when the issuer of the Logout Request does not match the IdP entityId" do
      settings.idp_entity_id = "http://idp.example.com/invalid"
      logout_request.soft = false
      err = assert_raises(Saml::ValidationError) do
        logout_request.spec_send(:validate_issuer)
      end
      assert_includes err.message.to_s, "Doesn't match the issuer, expected: <#{settings.idp_entity_id}>, but was: <https://app.onelogin.com/saml/metadata/SOMEACCOUNT>"
    end
  end

  describe "#validate_signature" do
    before do
      settings.security[:logout_requests_signed] = true
      settings.certificate = crystal_saml_cert_text
      settings.private_key = crystal_saml_key_text
      settings.idp_cert = crystal_saml_cert_text
    end

    it "return true when no idp_cert is provided and option relax_signature_validation is present" do
      settings.idp_cert = nil
      settings.security[:signature_method] = XMLSecurity::Document::RSA_SHA1
      params = Saml::Logoutrequest.new.create_params(settings, {"RelayState" => "http://example.com"})
      options = signature_options(params)
      options[:relax_signature_validation] = true
      logout_request_sign_test = Saml::SloLogoutrequest.new(params["SAMLRequest"], options)
      logout_request_sign_test.settings = settings
      assert logout_request_sign_test.spec_send(:validate_signature)
    end

    it "return false when no idp_cert is provided and no option relax_signature_validation is present" do
      settings.idp_cert = nil
      settings.security[:signature_method] = XMLSecurity::Document::RSA_SHA1
      params = Saml::Logoutrequest.new.create_params(settings, {"RelayState" => "http://example.com"})
      options = signature_options(params)
      logout_request_sign_test = Saml::SloLogoutrequest.new(params["SAMLRequest"], options)
      logout_request_sign_test.settings = settings
      assert !logout_request_sign_test.spec_send(:validate_signature)
    end

    it "return true when valid RSA_SHA1 Signature" do
      settings.security[:signature_method] = XMLSecurity::Document::RSA_SHA1
      params = Saml::Logoutrequest.new.create_params(settings, {"RelayState" => "http://example.com"})
      options = signature_options(params)
      logout_request_sign_test = Saml::SloLogoutrequest.new(params["SAMLRequest"], options)
      logout_request_sign_test.settings = settings
      assert logout_request_sign_test.spec_send(:validate_signature)
    end

    it "return true when valid RSA_SHA256 Signature" do
      settings.security[:signature_method] = XMLSecurity::Document::RSA_SHA256
      params = Saml::Logoutrequest.new.create_params(settings, {"RelayState" => "http://example.com"})
      options = signature_options(params)
      logout_request_sign_test = Saml::SloLogoutrequest.new(params["SAMLRequest"], options)
      logout_request_sign_test.settings = settings
      assert logout_request_sign_test.spec_send(:validate_signature)
    end

    it "return false when invalid RSA_SHA1 Signature" do
      settings.security[:signature_method] = XMLSecurity::Document::RSA_SHA1
      params = Saml::Logoutrequest.new.create_params(settings, {"RelayState" => "http://example.com"})
      params["RelayState"] = "http://invalid.example.com"
      options = signature_options(params)

      logout_request_sign_test = Saml::SloLogoutrequest.new(params["SAMLRequest"], options)
      logout_request_sign_test.settings = settings
      assert !logout_request_sign_test.spec_send(:validate_signature)
    end

    it "raise when invalid RSA_SHA1 Signature" do
      settings.security[:signature_method] = XMLSecurity::Document::RSA_SHA1
      settings.soft = false
      params = Saml::Logoutrequest.new.create_params(settings, {"RelayState" => "http://example.com"})
      params["RelayState"] = "http://invalid.example.com"
      options = signature_options(params)
      options[:settings] = settings

      logout_request_sign_test = Saml::SloLogoutrequest.new(params["SAMLRequest"], options)
      err = assert_raises(Saml::ValidationError) do
        logout_request_sign_test.spec_send(:validate_signature)
      end
      assert_includes err.message.to_s, "Invalid Signature on Logout Request"
    end

    it "raise when get_params encoding differs from what this library generates" do
      # Use Logoutrequest only to build the SAMLRequest parameter.
      settings.security[:signature_method] = XMLSecurity::Document::RSA_SHA1
      settings.soft = false
      params = Saml::Logoutrequest.new.create_params(settings, {"RelayState" => "http://example.com"})
      # Assemble query string.
      query = Saml::Utils.build_query({
        type:        "SAMLRequest",
        data:        params["SAMLRequest"],
        relay_state: params["RelayState"],
        sig_alg:     params["SigAlg"],
      })
      # Modify the query string so that it encodes the same values,
      # but with different percent-encoding. Sanity-check that they
      # really are equialent before moving on.
      original_query = query
      query = query.gsub("example", "ex%61mple")
      refute_equal(query, original_query)
      assert_equal(URI.decode(query), URI.decode(original_query))
      # Make normalised signature based on our modified params.
      sign_algorithm = XMLSecurity::BaseDocument.algorithm(settings.security[:signature_method].as(String))
      signature = settings.get_sp_key.not_nil!.sign(sign_algorithm, query)
      params["Signature"] = Base64.strict_encode(signature)
      # Construct SloLogoutrequest and ask it to validate the signature.
      # It will do it incorrectly, because it will compute it based on re-encoded
      # query parameters, rather than their original encodings.
      options = signature_options(params)
      options[:settings] = settings
      logout_request_sign_test = Saml::SloLogoutrequest.new(params["SAMLRequest"], options)
      err = assert_raises(Saml::ValidationError) do
        logout_request_sign_test.spec_send(:validate_signature)
      end
      assert_includes err.message.to_s, "Invalid Signature on Logout Request"
    end

    it "return true even if raw_get_params encoding differs from what this library generates" do
      # Use Logoutrequest only to build the SAMLRequest parameter.
      settings.security[:signature_method] = XMLSecurity::Document::RSA_SHA1
      settings.soft = false
      params = Saml::Logoutrequest.new.create_params(settings, {"RelayState" => "http://example.com"})
      # Assemble query string.
      query = Saml::Utils.build_query({
        type:        "SAMLRequest",
        data:        params["SAMLRequest"],
        relay_state: params["RelayState"],
        sig_alg:     params["SigAlg"],
      })
      # Modify the query string so that it encodes the same values,
      # but with different percent-encoding. Sanity-check that they
      # really are equialent before moving on.
      original_query = query
      query = query.gsub("example", "ex%61mple")
      refute_equal(query, original_query)
      assert_equal(URI.decode(query), URI.decode(original_query))
      # Make normalised signature based on our modified params.
      sign_algorithm = XMLSecurity::BaseDocument.algorithm(settings.security[:signature_method].as(String))
      signature = settings.get_sp_key.not_nil!.sign(sign_algorithm, query)
      params["Signature"] = Base64.strict_encode(signature)
      # Construct SloLogoutrequest and ask it to validate the signature.
      # Provide the altered parameter in its raw URI-encoded form,
      # so that we don't have to guess the value that contributed to the signature.
      options = signature_options(params)
      params.delete("RelayState")
      options[:raw_get_params] = {
        "RelayState" => "http%3A%2F%2Fex%61mple.com",
      }
      options[:settings] = settings
      logout_request_sign_test = Saml::SloLogoutrequest.new(params["SAMLRequest"], options)
      assert logout_request_sign_test.spec_send(:validate_signature)
    end

    it "handles Azure AD downcased request encoding" do
      # Use Logoutrequest only to build the SAMLRequest parameter.
      settings.security[:signature_method] = XMLSecurity::Document::RSA_SHA256
      settings.soft = false

      # Creating the query manually to tweak it later instead of using
      # Saml::Utils.build_query
      request_doc = Saml::Logoutrequest.new.create_logout_request_xml_doc(settings)
      base64_request = Base64.strict_encode(deflate(request_doc.to_s))
      # The original request received from Azure AD comes with downcased
      # encoded characters, like %2f instead of %2F, and the signature they
      # send is based on this base64 request.
      params = {
        "SAMLRequest" => downcased_escape(base64_request),
        "SigAlg"      => downcased_escape(settings.security[:signature_method].to_s),
      }
      # Assemble query string.
      query = "SAMLRequest=#{params["SAMLRequest"]}&SigAlg=#{params["SigAlg"]}"
      # Make normalised signature based on our modified params.
      sign_algorithm = XMLSecurity::BaseDocument.algorithm(settings.security[:signature_method].to_s)
      signature = settings.get_sp_key.not_nil!.sign(sign_algorithm, query)
      params["Signature"] = downcased_escape(Base64.strict_encode(signature))

      # Then parameters are usually unescaped, like we manage them in rails
      params = params.transform_values { |value| URI.decode_www_form(value) }
      # Construct SloLogoutrequest and ask it to validate the signature.
      # It will fail because the signature is based on the downcased request
      logout_request_downcased_test = Saml::SloLogoutrequest.new(params["SAMLRequest"], {:get_params => params, :settings => settings})
      err = assert_raises(Saml::ValidationError) do
        logout_request_downcased_test.spec_send(:validate_signature)
      end
      assert_includes err.message.to_s, "Invalid Signature on Logout Request"

      # For this case, the parameters will be forced to be downcased after
      # being escaped with :lowercase_url_encoding security option
      settings.security[:lowercase_url_encoding] = true
      logout_request_force_downcasing_test = Saml::SloLogoutrequest.new(params["SAMLRequest"], {:get_params => params, :settings => settings})
      assert logout_request_force_downcasing_test.spec_send(:validate_signature)
    end
  end

  describe "#validate_signature with multiple idp certs" do
    before do
      settings.certificate = crystal_saml_cert_text
      settings.private_key = crystal_saml_key_text
      settings.idp_cert = nil
      settings.security[:logout_requests_signed] = true
      settings.security[:signature_method] = XMLSecurity::Document::RSA_SHA1
    end

    it "return true when at least a idp_cert is valid" do
      params = Saml::Logoutrequest.new.create_params(settings, {"RelayState" => "http://example.com"})
      options = signature_options(params)
      logout_request_sign_test = Saml::SloLogoutrequest.new(params["SAMLRequest"], options)
      settings.idp_cert_multi = {
        :signing    => [crystal_saml_cert_text2, crystal_saml_cert_text],
        :encryption => [] of String,
      }
      logout_request_sign_test.settings = settings
      assert logout_request_sign_test.spec_send(:validate_signature)
    end

    it "return false when cert expired and check_idp_cert_expiration expired" do
      params = Saml::Logoutrequest.new.create_params(settings, {"RelayState" => "http://example.com"})
      options = signature_options(params)
      settings.security[:check_idp_cert_expiration] = true
      logout_request_sign_test = Saml::SloLogoutrequest.new(params["SAMLRequest"], options)
      settings.idp_cert = nil
      settings.idp_cert_multi = {
        :signing    => [crystal_saml_cert_text],
        :encryption => [] of String,
      }
      logout_request_sign_test.settings = settings
      assert !logout_request_sign_test.spec_send(:validate_signature)
      assert_includes logout_request_sign_test.errors, "IdP x509 certificate expired"
    end

    it "return false when none cert on idp_cert_multi is valid" do
      params = Saml::Logoutrequest.new.create_params(settings, {"RelayState" => "http://example.com"})
      options = signature_options(params)
      logout_request_sign_test = Saml::SloLogoutrequest.new(params["SAMLRequest"], options)
      settings.idp_cert_fingerprint = crystal_saml_cert_fingerprint
      settings.idp_cert_multi = {
        :signing    => [crystal_saml_cert_text2, crystal_saml_cert_text2],
        :encryption => [] of String,
      }
      logout_request_sign_test.settings = settings
      assert !logout_request_sign_test.spec_send(:validate_signature)
      assert_includes logout_request_sign_test.errors, "Invalid Signature on Logout Request"
    end
  end

  describe "strict message handling" do
    it "validates a signed RSA_SHA256 redirect request end to end" do
      settings.idp_entity_id = "http://sp.example.com/metadata"
      settings.sp_entity_id = "http://sp.example.com/metadata"
      settings.security[:logout_requests_signed] = true
      settings.security[:signature_method] = XMLSecurity::Document::RSA_SHA256
      settings.certificate = crystal_saml_cert_text
      settings.private_key = crystal_saml_key_text
      settings.idp_cert = crystal_saml_cert_text
      settings.name_identifier_value = "someone@example.org"
      settings.sessionindex = "_session_1"
      params = Saml::Logoutrequest.new.create_params(settings, {"RelayState" => "http://example.com/back"})
      options = signature_options(params)
      options[:settings] = settings

      request = Saml::SloLogoutrequest.new(params["SAMLRequest"], options)
      assert request.is_valid?, request.errors.inspect
      assert_equal "someone@example.org", request.nameid
      assert_equal ["_session_1"], request.session_indexes
    end

    # DOCTYPE/ENTITY declarations are refused rather than expanded.
    it "rejects a request with a DOCTYPE" do
      xml = %(<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY x "y">]>) + read_logout_request("slo_request.xml")
      request = Saml::SloLogoutrequest.new(Base64.strict_encode(xml), {:settings => settings})
      assert !request.is_valid?
      assert request.errors.any?(&.includes?("Doctype"))
    end

    # Malformed XML is a load error, never repaired.
    it "rejects malformed xml" do
      xml = read_logout_request("slo_request.xml").sub("</samlp:LogoutRequest>", "")
      request = Saml::SloLogoutrequest.new(Base64.strict_encode(xml), {:settings => settings})
      assert !request.is_valid?
      refute_empty request.errors
    end

    it "rejects a request over message_max_bytesize" do
      settings.message_max_bytesize = 100
      assert_raises(Saml::ValidationError) do
        Saml::SloLogoutrequest.new(logout_request_document, {:settings => settings})
      end
    end

    # An invalid NotOnOrAfter is an error, not a missing condition.
    it "rejects an unparseable NotOnOrAfter" do
      logout_request.document.root.not_nil!["NotOnOrAfter"] = "not a time"
      assert !logout_request.spec_send(:validate_not_on_or_after)
      assert_includes logout_request.errors, "Invalid NotOnOrAfter value"
    end
  end
end
