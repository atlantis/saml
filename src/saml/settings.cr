# Only supports SAML 2.0
module Saml

  # SAML2 Toolkit Settings
  #
  class Settings
    alias Value = String | Int32 | Bool

    @single_logout_service_binding : String?

    # IdP Data
    property :idp_entity_id
    setter idp_sso_service_url : String?
    setter idp_slo_service_url : String?
    property idp_slo_response_service_url : String?
    property idp_cert : String?
    property idp_cert_fingerprint : String?
    property idp_cert_fingerprint_algorithm : String?
    property idp_cert_multi = {} of Symbol => Array(String)
    property :idp_attribute_names
    property :idp_name_qualifier
    property :valid_until
    # SP Data
    setter sp_entity_id : String?
    property assertion_consumer_service_url : String?
    getter assertion_consumer_service_binding : String?
    setter single_logout_service_url : String?
    property sp_name_qualifier : String?
    property :name_identifier_format
    property :name_identifier_value
    property :name_identifier_value_requested
    property :sessionindex
    property compress_request : Bool = true
    property compress_response : Bool = true
    property double_quote_xml_attribute_values : Bool = true
    property message_max_bytesize : Int32 = 250000
    property :passive
    getter protocol_binding : String?
    property :attributes_index
    property :force_authn
    property :certificate
    property :certificate_new
    property private_key : String?
    property :authn_context
    property :authn_context_comparison
    property :authn_context_decl_ref
    getter :attribute_consuming_service
    # Work-flow
    property security = {} of Symbol => Value
    property soft : Bool = true
    # Deprecated
    property :assertion_consumer_logout_service_url
    getter :assertion_consumer_logout_service_binding
    property :issuer
    property :idp_sso_target_url
    property :idp_slo_target_url

    DEFAULTS = {
      :assertion_consumer_service_binding => Utils::BINDINGS[:post],
      :single_logout_service_binding => Utils::BINDINGS[:redirect],
      :idp_cert_fingerprint_algorithm => XMLSecurity::Document::SHA1,
      :compress_request => true,
      :compress_response => true,
      :message_max_bytesize => 250000,
      :soft => true,
      :double_quote_xml_attribute_values => false,
      :security => {
        :authn_requests_signed => false,
        :logout_requests_signed => false,
        :logout_responses_signed => false,
        :want_assertions_signed => false,
        :want_assertions_encrypted => false,
        :want_name_id => false,
        :metadata_signed => false,
        :embed_sign => false, # Deprecated
        :digest_method => XMLSecurity::Document::SHA1,
        :signature_method => XMLSecurity::Document::RSA_SHA1,
        :check_idp_cert_expiration => false,
        :check_sp_cert_expiration => false,
        :strict_audience_validation => false,
        :lowercase_url_encoding => false,
      },
    }

    def initialize(overrides = {} of Symbol => Value | Hash(Symbol, Value), keep_security_attributes = false)
      # if keep_security_attributes
      #   security_attributes = overrides.delete(:security).as?(Hash(Symbol, Value)) || {} of Symbol => Value
      #   config = DEFAULTS.merge(overrides)
      #   if security_defaults = DEFAULTS[:security].as?( Hash(Symbol, Value) )
      #     config[:security] = security_defaults.merge(security_attributes)
      #   end
      # else
      # Can't find where keep_security_attributes is used?
        config = DEFAULTS.merge(overrides)
      # end

      config.each do |k, v|
        # TODO: replace with slick macro
        case k
        when :assertion_consumer_service_binding
          self.assertion_consumer_service_binding = v.as?(String)
        when :single_logout_service_binding
          self.single_logout_service_binding = v.as?(String)
        when :idp_cert_fingerprint_algorithm
          self.idp_cert_fingerprint_algorithm = v.as?(String)
        when :compress_request
          self.compress_request = v.as(Bool)
        when :compress_response
          self.compress_response = v.as(Bool)
        when :message_max_bytesize
          self.message_max_bytesize = v.as(Int32)
        when :soft
          self.soft = v.as(Bool)
        when :double_quote_xml_attribute_values
          self.double_quote_xml_attribute_values = v.as(Bool)
        end
      end
      @attribute_consuming_service = AttributeService.new
    end

    # @return [String] IdP Single Sign On Service URL
    #
    def idp_sso_service_url
      @idp_sso_service_url || @idp_sso_target_url
    end

    # @return [String] IdP Single Logout Service URL
    #
    def idp_slo_service_url
      @idp_slo_service_url || @idp_slo_target_url
    end

    # @return [String] IdP Single Sign On Service Binding
    #
    def idp_sso_service_binding
      @idp_sso_service_binding || idp_binding_from_embed_sign
    end

    # Setter for IdP Single Sign On Service Binding
    # @param value [String, Symbol].
    #
    def idp_sso_service_binding=(value)
      @idp_sso_service_binding = get_binding(value)
    end

    # @return [String] IdP Single Logout Service Binding
    #
    def idp_slo_service_binding
      @idp_slo_service_binding || idp_binding_from_embed_sign
    end

    # Setter for IdP Single Logout Service Binding
    # @param value [String, Symbol].
    #
    def idp_slo_service_binding=(value)
      @idp_slo_service_binding = get_binding(value)
    end

    # @return [String] SP Entity ID
    #
    def sp_entity_id
      @sp_entity_id || @issuer
    end

    # Setter for SP Protocol Binding
    # @param value [String, Symbol].
    #
    def protocol_binding=(value)
      @protocol_binding = get_binding(value)
    end

    # Setter for SP Assertion Consumer Service Binding
    # @param value [String, Symbol].
    #
    def assertion_consumer_service_binding=(value)
      @assertion_consumer_service_binding = get_binding(value)
    end

    # @return [String] Single Logout Service URL.
    #
    def single_logout_service_url
      @single_logout_service_url || @assertion_consumer_logout_service_url
    end

    # @return [String] Single Logout Service Binding.
    #
    def single_logout_service_binding
      @single_logout_service_binding || @assertion_consumer_logout_service_binding
    end

    # Setter for Single Logout Service Binding.
    #
    # (Currently we only support "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect")
    # @param value [String, Symbol]
    #
    def single_logout_service_binding=(value)
      @single_logout_service_binding = get_binding(value)
    end

    # @deprecated Setter for legacy Single Logout Service Binding parameter.
    #
    # (Currently we only support "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect")
    # @param value [String, Symbol]
    #
    def assertion_consumer_logout_service_binding=(value)
      @assertion_consumer_logout_service_binding = get_binding(value)
    end

    # Calculates the fingerprint of the IdP x509 certificate.
    # @return [String] The fingerprint
    #
    def get_fingerprint
      idp_cert_fingerprint || begin
        idp_cert = get_idp_cert
        if idp_cert
          fingerprint_alg = XMLSecurity::BaseDocument.algorithm(idp_cert_fingerprint_algorithm)
          fingerprint_alg.hexdigest(idp_cert.to_der).upcase.scan(/../).join(":")
        end
      end
    end

    # @return [OpenSSL::X509::Certificate|nil] Build the IdP certificate from the settings (previously format it)
    #
    def get_idp_cert
      return nil if idp_cert.nil? || idp_cert.empty?

      formatted_cert = Saml::Utils.format_cert(idp_cert.not_nil!)
      OpenSSL::X509::Certificate.new(formatted_cert)
    end

    # @return [Hash with 2 arrays of OpenSSL::X509::Certificate] Build multiple IdP certificates from the settings.
    #
    def get_idp_cert_multi
      return nil if idp_cert_multi.nil? || idp_cert_multi.empty?

      raise ArgumentError.new("Invalid value for idp_cert_multi") if !idp_cert_multi.is_a?(Hash)

      certs = { :signing => [] of String, :encryption => [] of String }

      [:signing, :encryption].each do |type|
        certs_for_type = idp_cert_multi[type] || idp_cert_multi[type.to_s]
        next if !certs_for_type || certs_for_type.empty?

        certs_for_type.each do |idp_cert|
          formatted_cert = Saml::Utils.format_cert(idp_cert)
          certs[type].push(OpenSSL::X509::Certificate.new(formatted_cert))
        end
      end

      certs
    end

    # @return [OpenSSL::X509::Certificate|nil] Build the SP certificate from the settings (previously format it)
    #
    def get_sp_cert
      return nil if certificate.nil? || certificate.empty?

      formatted_cert = Saml::Utils.format_cert(certificate)
      cert = OpenSSL::X509::Certificate.new(formatted_cert)

      if security[:check_sp_cert_expiration]
        if Saml::Utils.is_cert_expired(cert)
          raise Saml::ValidationError.new("The SP certificate expired.")
        end
      end

      cert
    end

    # @return [OpenSSL::X509::Certificate|nil] Build the New SP certificate from the settings (previously format it)
    #
    def get_sp_cert_new
      return nil if certificate_new.nil? || certificate_new.empty?

      formatted_cert = Saml::Utils.format_cert(certificate_new)
      OpenSSL::X509::Certificate.new(formatted_cert)
    end

    # @return [OpenSSL::PKey::RSA] Build the SP private from the settings (previously format it)
    #
    def get_sp_key
      if key = self.private_key
        formatted_private_key = Saml::Utils.format_private_key(key)
        OpenSSL::PKey::RSA.new(formatted_private_key)
      end
    end

    def idp_binding_from_embed_sign
      security[:embed_sign] ? Utils::BINDINGS[:post] : Utils::BINDINGS[:redirect]
    end

    def get_binding(value) : String?
      return unless value

      case value
      when :post, "post"
        Utils::BINDINGS[:post]
      when :redirect, "redirect"
        Utils::BINDINGS[:redirect]
      else
        raise "Invalid binding: #{value}"
      end
    end
  end
end
