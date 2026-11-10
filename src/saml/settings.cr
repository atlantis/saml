# Only supports SAML 2.0
module Saml
  # SAML2 Toolkit Settings. Build one per request from stored configuration;
  # nothing here is global.
  #
  class Settings
    alias SecurityValue = String | Int32 | Bool | Nil
    alias Value = String | Int32 | Bool | Time | Symbol | Array(String) | Hash(Symbol, Array(String)) | Hash(Symbol, SecurityValue) | Nil

    DEFAULT_SECURITY = {
      :authn_requests_signed      => false,
      :logout_requests_signed     => false,
      :logout_responses_signed    => false,
      :want_assertions_signed     => false,
      :want_assertions_encrypted  => false,
      :want_name_id               => false,
      :metadata_signed            => false,
      :embed_sign                 => false, # Deprecated
      :digest_method              => XMLSecurity::Document::SHA1,
      :signature_method           => XMLSecurity::Document::RSA_SHA1,
      :check_idp_cert_expiration  => false,
      :check_sp_cert_expiration   => false,
      :strict_audience_validation => false,
      :lowercase_url_encoding     => false,
    } of Symbol => SecurityValue

    DEFAULTS = {
      :assertion_consumer_service_binding => Utils::BINDINGS[:post],
      :single_logout_service_binding      => Utils::BINDINGS[:redirect],
      :idp_cert_fingerprint_algorithm     => XMLSecurity::Document::SHA1,
      :compress_request                   => true,
      :compress_response                  => true,
      :message_max_bytesize               => 250000,
      :soft                               => true,
      :check_malformed_doc                => true,
      :double_quote_xml_attribute_values  => false,
      :security                           => DEFAULT_SECURITY,
    } of Symbol => Value

    # IdP Data
    property idp_entity_id : String?
    setter idp_sso_service_url : String?
    setter idp_slo_service_url : String?
    property idp_slo_response_service_url : String?
    property idp_cert : String?
    property idp_cert_fingerprint : String?
    property idp_cert_fingerprint_algorithm : String?
    getter idp_cert_multi : Hash(Symbol, Array(String))? = nil
    property idp_attribute_names : Array(String)?
    property idp_name_qualifier : String?
    getter valid_until : Time?
    # SP Data
    setter sp_entity_id : String?
    property assertion_consumer_service_url : String?
    getter assertion_consumer_service_binding : String?
    setter single_logout_service_url : String?
    property sp_name_qualifier : String?
    property name_identifier_format : String?
    property name_identifier_value : String?
    property name_identifier_value_requested : String?
    property sessionindex : String?
    property compress_request : Bool = true
    property compress_response : Bool = true
    property double_quote_xml_attribute_values : Bool = false
    property message_max_bytesize : Int32 = 250000
    # Malformed XML is always refused; kept for compatibility.
    property check_malformed_doc : Bool = true
    property passive : Bool?
    getter protocol_binding : String?
    property attributes_index : Int32?
    property force_authn : Bool?
    property certificate : String?
    property certificate_new : String?
    property private_key : String?
    property authn_context : String | Array(String) | Nil
    property authn_context_comparison : String?
    property authn_context_decl_ref : String | Array(String) | Nil
    getter attribute_consuming_service : AttributeService
    # Work-flow
    property security : Hash(Symbol, SecurityValue)
    property soft : Bool = true
    # Deprecated
    property assertion_consumer_logout_service_url : String?
    getter assertion_consumer_logout_service_binding : String?
    property issuer : String?
    property idp_sso_target_url : String?
    property idp_slo_target_url : String?

    @idp_sso_service_binding : String?
    @idp_slo_service_binding : String?
    @single_logout_service_binding : String?

    # *overrides* maps setting names (symbols) to values; a :security hash
    # replaces the default security settings unless *keep_security_attributes*,
    # in which case it is merged over them.
    def initialize(overrides : Hash = {} of Symbol => Value, keep_security_attributes = false)
      @security = DEFAULT_SECURITY.dup
      @attribute_consuming_service = AttributeService.new

      DEFAULTS.each do |key, value|
        set_option(key, value) unless key == :security
      end

      overrides.each do |key, value|
        if key.to_s == "security"
          security = to_security(value)
          @security = keep_security_attributes ? DEFAULT_SECURITY.merge(security) : security
        else
          set_option(key, value)
        end
      end
    end

    # Sets one setting by name; unknown names are ignored. Returns whether the
    # name was known.
    def set_option(key : Symbol | String, value) : Bool
      {% begin %}
        case key.to_s
        {% for name in %w(idp_entity_id idp_sso_service_url idp_slo_service_url idp_slo_response_service_url idp_cert
                         idp_cert_fingerprint idp_cert_fingerprint_algorithm idp_name_qualifier sp_entity_id
                         assertion_consumer_service_url sp_name_qualifier name_identifier_format name_identifier_value
                         name_identifier_value_requested sessionindex certificate certificate_new private_key
                         authn_context_comparison assertion_consumer_logout_service_url issuer idp_sso_target_url
                         idp_slo_target_url) %}
        when {{name}} then self.{{name.id}} = value.nil? ? nil : value.to_s
        {% end %}
        {% for name in %w(compress_request compress_response double_quote_xml_attribute_values check_malformed_doc soft) %}
        when {{name}} then self.{{name.id}} = value == true
        {% end %}
        {% for name in %w(passive force_authn) %}
        when {{name}} then self.{{name.id}} = value.nil? ? nil : value == true
        {% end %}
        {% for name in %w(idp_sso_service_binding idp_slo_service_binding protocol_binding assertion_consumer_service_binding
                         single_logout_service_binding assertion_consumer_logout_service_binding) %}
        when {{name}} then self.{{name.id}} = value.is_a?(Symbol) ? value : value.try(&.to_s)
        {% end %}
        when "message_max_bytesize"
          self.message_max_bytesize = value.to_s.to_i
        when "attributes_index"
          self.attributes_index = value.nil? ? nil : value.to_s.to_i
        when "valid_until"
          self.valid_until = value.is_a?(Time) ? value : value.try(&.to_s)
        when "idp_attribute_names"
          self.idp_attribute_names = value.is_a?(Array) ? value.map(&.to_s) : nil
        when "idp_cert_multi"
          self.idp_cert_multi = value.is_a?(Hash) ? value : nil
        when "authn_context", "authn_context_decl_ref"
          context = case value
                    when Array then value.map(&.to_s)
                    when nil   then nil
                    else            value.to_s
                    end
          key.to_s == "authn_context" ? (self.authn_context = context) : (self.authn_context_decl_ref = context)
        when "security"
          @security = to_security(value)
        else
          return false
        end
      {% end %}
      true
    end

    private def to_security(value) : Hash(Symbol, SecurityValue)
      result = {} of Symbol => SecurityValue
      if value.is_a?(Hash)
        value.each do |k, v|
          next unless k.is_a?(Symbol)
          result[k] = v.is_a?(SecurityValue) ? v : v.to_s
        end
      end
      result
    end

    def valid_until=(value : Time?)
      @valid_until = value
    end

    def valid_until=(value : String)
      @valid_until = Time::Format::ISO_8601_DATE_TIME.parse(value)
    end

    def idp_cert_multi=(value : Nil)
      @idp_cert_multi = nil
    end

    # Accepts symbol or string keys (:signing / :encryption).
    def idp_cert_multi=(value : Hash)
      result = {} of Symbol => Array(String)
      value.each do |k, v|
        name = k.to_s
        next unless name == "signing" || name == "encryption"
        result[name == "signing" ? :signing : :encryption] = v.is_a?(Array) ? v.map(&.to_s) : [] of String
      end
      # Unknown keys still count as set, as in ruby-saml.
      result = {:signing => [] of String, :encryption => [] of String} if result.empty? && !value.empty?
      @idp_cert_multi = result
    end

    # @return [String] IdP Single Sign On Service URL
    def idp_sso_service_url : String?
      @idp_sso_service_url || @idp_sso_target_url
    end

    # @return [String] IdP Single Logout Service URL
    def idp_slo_service_url : String?
      @idp_slo_service_url || @idp_slo_target_url
    end

    # @return [String] IdP Single Sign On Service Binding
    def idp_sso_service_binding : String?
      @idp_sso_service_binding || idp_binding_from_embed_sign
    end

    def idp_sso_service_binding=(value : String | Symbol | Nil)
      @idp_sso_service_binding = get_binding(value)
    end

    # @return [String] IdP Single Logout Service Binding
    def idp_slo_service_binding : String?
      @idp_slo_service_binding || idp_binding_from_embed_sign
    end

    def idp_slo_service_binding=(value : String | Symbol | Nil)
      @idp_slo_service_binding = get_binding(value)
    end

    # @return [String] SP Entity ID
    def sp_entity_id : String?
      @sp_entity_id || @issuer
    end

    def protocol_binding=(value : String | Symbol | Nil)
      @protocol_binding = get_binding(value)
    end

    def assertion_consumer_service_binding=(value : String | Symbol | Nil)
      @assertion_consumer_service_binding = get_binding(value)
    end

    # @return [String] Single Logout Service URL.
    def single_logout_service_url : String?
      @single_logout_service_url || @assertion_consumer_logout_service_url
    end

    # @return [String] Single Logout Service Binding.
    def single_logout_service_binding : String?
      @single_logout_service_binding || @assertion_consumer_logout_service_binding
    end

    def single_logout_service_binding=(value : String | Symbol | Nil)
      @single_logout_service_binding = get_binding(value)
    end

    def assertion_consumer_logout_service_binding=(value : String | Symbol | Nil)
      @assertion_consumer_logout_service_binding = get_binding(value)
    end

    # Calculates the fingerprint of the IdP x509 certificate.
    def get_fingerprint : String?
      idp_cert_fingerprint || begin
        if cert = get_idp_cert
          fingerprint_alg = XMLSecurity::BaseDocument.algorithm(idp_cert_fingerprint_algorithm)
          fingerprint_alg << cert.to_der
          fingerprint_alg.hexfinal.upcase.scan(/../).map(&.[0]).join(":")
        end
      end
    end

    # @return [OpenSSL::X509::Certificate|nil] Build the IdP certificate from the settings
    def get_idp_cert : OpenSSL::X509::Certificate?
      Utils.build_cert_object(idp_cert)
    end

    # @return [Hash with 2 arrays of OpenSSL::X509::Certificate] Build multiple IdP certificates from the settings.
    def get_idp_cert_multi : Hash(Symbol, Array(OpenSSL::X509::Certificate))?
      multi = idp_cert_multi
      return nil if multi.nil? || multi.empty?

      certs = {:signing => [] of OpenSSL::X509::Certificate, :encryption => [] of OpenSSL::X509::Certificate}
      [:signing, :encryption].each do |type|
        (multi[type]? || [] of String).each do |idp_cert|
          if cert = Utils.build_cert_object(idp_cert)
            certs[type] << cert
          end
        end
      end

      certs
    end

    # Every IdP signing certificate configured (the multi list, else idp_cert).
    def idp_signing_certificates : Array(OpenSSL::X509::Certificate)
      if (multi = get_idp_cert_multi) && !multi[:signing].empty?
        multi[:signing]
      elsif cert = get_idp_cert
        [cert]
      else
        [] of OpenSSL::X509::Certificate
      end
    end

    # @return [OpenSSL::X509::Certificate|nil] The SP certificate
    def get_sp_cert : OpenSSL::X509::Certificate?
      cert = Utils.build_cert_object(certificate)
      if cert && security[:check_sp_cert_expiration]? == true && !Utils.is_cert_active(cert)
        raise ValidationError.new("The SP certificate expired.")
      end
      cert
    end

    # @return [OpenSSL::X509::Certificate|nil] The new SP certificate (during a rotation)
    def get_sp_cert_new : OpenSSL::X509::Certificate?
      Utils.build_cert_object(certificate_new)
    end

    # @return [OpenSSL::PKey::RSA|nil] The SP private key
    def get_sp_key : OpenSSL::PKey::RSA?
      Utils.build_private_key_object(private_key)
    end

    def get_sp_key_text : String?
      Utils.format_private_key(private_key)
    end

    # Keys an encrypted assertion may be decrypted with.
    def get_sp_decryption_keys : Array(OpenSSL::PKey::RSA)
      (key = get_sp_key) ? [key] : [] of OpenSSL::PKey::RSA
    end

    def idp_binding_from_embed_sign : String
      security[:embed_sign]? == true ? Utils::BINDINGS[:post] : Utils::BINDINGS[:redirect]
    end

    def get_binding(value : String | Symbol | Nil) : String?
      case value
      when nil                   then nil
      when :post, "post"         then Utils::BINDINGS[:post]
      when :redirect, "redirect" then Utils::BINDINGS[:redirect]
      else                            value.to_s
      end
    end
  end
end
