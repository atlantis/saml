require "./spec_helper"

# expose private methods for tests
module Saml
  class Response
    def send(method : Symbol, option : XML::Node? = nil)
      case method
      when :decrypt_assertion
        self.decrypt_assertion(option.not_nil!)
      when :xpath_first_from_signed_assertion
        self.xpath_first_from_signed_assertion
      when :validate_signed_elements
        self.validate_signed_elements
      when :validate_structure
        self.validate_structure
      when :validate_audience
        self.validate_audience
      when :validate_destination
        self.validate_destination
      when :validate_issuer
        self.validate_issuer
      when :validate_num_assertion
        self.validate_num_assertion
      when :validate_success_status
        self.validate_success_status
      when :validate_in_response_to
        self.validate_in_response_to
      when :validate_subject_confirmation
        self.validate_subject_confirmation
      when :validate_session_expiration
        self.validate_session_expiration
      when :validate_signature
        self.validate_signature
      when :validate_name_id
        self.validate_name_id
      when :validate_one_authnstatement
        self.validate_one_authnstatement
      when :validate_conditions
        self.validate_conditions
      when :validate_no_duplicated_attributes
        self.validate_no_duplicated_attributes
      when :validate_one_conditions
        self.validate_one_conditions
      else
        raise "Missing .send hack for method #{method}"
      end
    end
  end

  class SpecialResponse1 < Saml::Response
    def initialize(response, options = {} of Symbol => OptionValue)
      super(response, options)
      @document = XMLSecurity::SpecialSignedDocument1.new(@response, @error_messages)

      if assertion_encrypted?
        @decrypted_document = generate_decrypted_document
      end
    end

    def validate_conditions
      true
    end
  end

  class SpecialResponse2 < Saml::Response
    def conditions
      nil
    end
  end

  class SpecialResponse3 < Saml::Response
    def conditions
      nil
    end

    def validate_subject_confirmation
      true
    end
  end

  class SpecialResponse4 < Saml::Response
    def conditions
      nil
    end
  end

  class SpecialResponse5 < Saml::Response
    def conditions
      nil
    end

    def validate_subject_confirmation
      true
    end

    def validate_signature
      true
    end
  end

  class SpecialSignedDocument1 < XMLSecurity::SignedDocument
    def digests_match?
      true
    end
  end
end

class RubySamlTest < Minitest::Test
  describe "Response" do
    let(:settings) { Saml::Settings.new }
    let(:response) { Saml::Response.new(response_document_without_recipient) }
    let(:response_without_attributes) { Saml::Response.new(response_document_without_attributes) }
    let(:response_with_multiple_attribute_statements) { Saml::Response.new(fixture(:response_with_multiple_attribute_statements)) }
    let(:response_without_reference_uri) { Saml::Response.new(response_document_without_reference_uri) }
    let(:response_without_reference_uri_special2) { Saml::SpecialResponse2.new(response_document_without_reference_uri) }
    let(:response_with_signed_assertion) { Saml::Response.new(response_document_with_signed_assertion) }
    let(:response_with_ds_namespace_at_the_root) { Saml::Response.new(response_document_with_ds_namespace_at_the_root) }
    let(:response_unsigned) { Saml::Response.new(response_document_unsigned) }
    let(:response_unsigned_special2) { Saml::SpecialResponse2.new(response_document_unsigned) }
    let(:response_wrapped) { Saml::Response.new(response_document_wrapped) }
    let(:response_wrapped_special2) { Saml::SpecialResponse2.new(response_document_wrapped) }
    let(:response_wrapped_special3) { Saml::SpecialResponse3.new(response_document_wrapped) }
    let(:response_multiple_attr_values) { Saml::Response.new(fixture(:response_with_multiple_attribute_values)) }
    let(:response_valid_signed) { Saml::Response.new(response_document_valid_signed) }
    let(:response_valid_signed_without_recipient) { Saml::Response.new(response_document_valid_signed, { :skip_recipient_check => true }) }
    let(:response_valid_signed_without_recipient_special4) { Saml::SpecialResponse4.new(response_document_valid_signed, { :skip_recipient_check => true }) }
    let(:response_valid_signed_without_x509certificate) { Saml::Response.new(response_document_valid_signed_without_x509certificate) }
    let(:response_no_id) { Saml::Response.new(read_invalid_response("no_id.xml.base64")) }
    let(:response_no_version) { Saml::Response.new(read_invalid_response("no_saml2.xml.base64")) }
    let(:response_multi_assertion) { Saml::Response.new(read_invalid_response("multiple_assertions.xml.base64")) }
    let(:response_no_conditions) { Saml::Response.new(read_invalid_response("no_conditions.xml.base64")) }
    let(:response_no_conditions_with_skip) { Saml::Response.new(read_invalid_response("no_conditions.xml.base64"), { :skip_conditions => true }) }
    let(:response_no_authnstatement) { Saml::Response.new(read_invalid_response("no_authnstatement.xml.base64")) }
    let(:response_no_authnstatement_with_skip) { Saml::Response.new(read_invalid_response("no_authnstatement.xml.base64"), { :skip_authnstatement => true }) }
    let(:response_empty_destination) { Saml::Response.new(read_invalid_response("empty_destination.xml.base64")) }
    let(:response_empty_destination_with_skip) { Saml::Response.new(read_invalid_response("empty_destination.xml.base64"), { :skip_destination => true }) }
    let(:response_no_status) { Saml::Response.new(read_invalid_response("no_status.xml.base64")) }
    let(:response_no_statuscode) { Saml::Response.new(read_invalid_response("no_status_code.xml.base64")) }
    let(:response_statuscode_responder) { Saml::Response.new(read_invalid_response("status_code_responder.xml.base64")) }
    let(:response_statuscode_responder_and_msg) { Saml::Response.new(read_invalid_response("status_code_responer_and_msg.xml.base64")) }
    let(:response_double_statuscode) { Saml::Response.new(response_document_double_status_code) }
    let(:response_encrypted_attrs) { Saml::Response.new(response_document_encrypted_attrs) }
    let(:response_no_signed_elements) { Saml::Response.new(read_invalid_response("no_signature.xml.base64")) }
    let(:response_multiple_signed) { Saml::Response.new(read_invalid_response("multiple_signed.xml.base64")) }
    let(:response_audience_self_closed) { Saml::Response.new(read_response("response_audience_self_closed_tag.xml.base64")) }
    let(:response_invalid_audience) { Saml::Response.new(read_invalid_response("invalid_audience.xml.base64")) }
    let(:response_invalid_audience_with_skip) { Saml::Response.new(read_invalid_response("invalid_audience.xml.base64"), { :skip_audience => true }) }
    let(:response_invalid_signed_element) { Saml::Response.new(read_invalid_response("response_invalid_signed_element.xml.base64")) }
    let(:response_invalid_issuer_assertion) { Saml::Response.new(read_invalid_response("invalid_issuer_assertion.xml.base64")) }
    let(:response_invalid_issuer_message) { Saml::Response.new(read_invalid_response("invalid_issuer_message.xml.base64")) }
    let(:response_no_issuer_response) { Saml::Response.new(read_invalid_response("no_issuer_response.xml.base64")) }
    let(:response_no_issuer_assertion) { Saml::Response.new(read_invalid_response("no_issuer_assertion.xml.base64")) }
    let(:response_no_nameid) { Saml::Response.new(read_invalid_response("no_nameid.xml.base64")) }
    let(:response_empty_nameid) { Saml::Response.new(read_invalid_response("empty_nameid.xml.base64")) }
    let(:response_wrong_spnamequalifier) { Saml::Response.new(read_invalid_response("wrong_spnamequalifier.xml.base64")) }
    let(:response_duplicated_attributes) { Saml::Response.new(read_invalid_response("duplicated_attributes.xml.base64")) }
    let(:response_no_subjectconfirmation_data) { Saml::Response.new(read_invalid_response("no_subjectconfirmation_data.xml.base64")) }
    let(:response_no_subjectconfirmation_method) { Saml::Response.new(read_invalid_response("no_subjectconfirmation_method.xml.base64")) }
    let(:response_invalid_subjectconfirmation_inresponse) { Saml::Response.new(read_invalid_response("invalid_subjectconfirmation_inresponse.xml.base64")) }
    let(:response_invalid_subjectconfirmation_recipient) { Saml::Response.new(read_invalid_response("invalid_subjectconfirmation_recipient.xml.base64")) }
    let(:response_invalid_subjectconfirmation_nb) { Saml::Response.new(read_invalid_response("invalid_subjectconfirmation_nb.xml.base64")) }
    let(:response_invalid_subjectconfirmation_noa) { Saml::Response.new(read_invalid_response("invalid_subjectconfirmation_noa.xml.base64")) }
    let(:response_invalid_signature_position) { Saml::Response.new(read_invalid_response("invalid_signature_position.xml.base64")) }
    let(:response_encrypted_nameid) { Saml::Response.new(response_document_encrypted_nameid) }

    describe "#check_one_conditions" do
      # it "return false when none or more than one conditions element" do
      #   response_no_conditions.soft = true
      #   assert !response_no_conditions.send(:validate_one_conditions)
      #   assert_includes response_no_conditions.errors, "The Assertion must include one Conditions element"
      # end

      # it "return true when one conditions element" do
      #   response.soft = true
      #   assert response.send(:validate_one_conditions)
      # end

      it "return true when no conditions are present and skip_conditions is true" do
        response_no_conditions_with_skip.soft = true
        puts "AFTER WRITE: #{response_no_conditions_with_skip.options.inspect}"
        assert response_no_conditions_with_skip.send(:validate_one_conditions)
      end
    end
  end
end