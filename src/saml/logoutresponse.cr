# Only supports SAML 2.0
module Saml
  # SAML2 Logout Response (SLO SP initiated, Parser)
  #
  # The signature is only checked when :get_params carry a Signature (the
  # HTTP-Redirect binding), as in ruby-saml.
  class Logoutresponse < SamlMessage
    include ErrorHandling
    include RedirectSignature

    property settings : Settings?
    getter document : XMLSecurity::SignedDocument
    getter response : String
    getter options : Hash(Symbol, RedirectSignature::OptionValue)
    property soft : Bool = true

    @in_response_to : String?
    @issuer : String?
    @status_code : String?
    @status_message : String?

    # @param response [String] A base64 encoded (and maybe deflated) logout response from the IdP.
    # @param settings [Settings|nil] Toolkit settings
    # @param options [Hash] :matches_request_id, :get_params / :raw_get_params,
    #   :relax_signature_validation
    # @raise [ArgumentError] if response is nil
    def initialize(response : String?, settings : Settings? = nil, options : Hash = {} of Symbol => RedirectSignature::OptionValue)
      raise ArgumentError.new("Logoutresponse cannot be nil") if response.nil?

      @error_messages = [] of String
      @settings = settings
      @soft = settings.nil? || settings.soft
      @options = {} of Symbol => RedirectSignature::OptionValue
      options.each { |key, value| @options[key] = value }

      @response = decode_raw_saml(response, settings)
      @document = XMLSecurity::SignedDocument.new(@response, @error_messages)
    end

    def response_id : String?
      id(document)
    end

    # Checks if the Status has the "Success" code
    def success? : Bool
      status_code == "urn:oasis:names:tc:SAML:2.0:status:Success"
    end

    # @return [String|nil] Gets the InResponseTo attribute from the Logout Response if exists.
    def in_response_to : String?
      @in_response_to ||= document.xpath_node("/p:LogoutResponse", {"p" => PROTOCOL}).try(&.[]?("InResponseTo"))
    end

    # @return [String] Gets the Issuer from the Logout Response.
    def issuer : String?
      @issuer ||= Utils.element_text(document.xpath_node("/p:LogoutResponse/a:Issuer", {"p" => PROTOCOL, "a" => ASSERTION}))
    end

    # @return [String] Gets the StatusCode from a Logout Response.
    def status_code : String?
      @status_code ||= document.xpath_node("/p:LogoutResponse/p:Status/p:StatusCode", {"p" => PROTOCOL}).try(&.[]?("Value"))
    end

    def status_message : String?
      @status_message ||= Utils.element_text(document.xpath_node("/p:LogoutResponse/p:Status/p:StatusMessage", {"p" => PROTOCOL}))
    end

    # Validates the Logout Response
    # @raise [ValidationError] if soft == false and validation fails
    def validate(collect_errors = false) : Bool
      reset_errors!

      validations = [
        -> { valid_state? },
        -> { validate_success_status },
        -> { validate_structure },
        -> { valid_in_response_to? },
        -> { valid_issuer? },
        -> { validate_signature },
      ]

      if collect_errors
        validations.each(&.call)
        @error_messages.empty?
      else
        validations.all?(&.call)
      end
    end

    private def validate_success_status : Bool
      return true if success?

      error_msg = "The status code of the Logout Response was not Success"
      append_error(Utils.status_error_msg(error_msg, status_code, status_message))
    end

    private def validate_structure : Bool
      unless valid_saml?(document, soft)
        return append_error("Invalid SAML Logout Response. Not match the saml-schema-protocol-2.0.xsd")
      end

      true
    end

    private def valid_state? : Bool
      return append_error("Blank logout response") if response.strip.empty?
      if load_error = document.load_error
        return append_error(load_error)
      end

      current = settings
      return append_error("No settings on logout response") if current.nil?
      return append_error("No sp_entity_id in settings of the logout response") if current.sp_entity_id.nil?

      if current.idp_cert_fingerprint.nil? && current.idp_cert.nil? && current.idp_cert_multi.nil?
        return append_error("No fingerprint or certificate on settings of the logout response")
      end

      true
    end

    private def valid_in_response_to? : Bool
      return true unless options.has_key?(:matches_request_id)
      expected = options[:matches_request_id]?
      return true if expected.nil?
      return true if expected.to_s == in_response_to

      append_error("The InResponseTo of the Logout Response: #{in_response_to}, does not match the ID of the Logout Request sent by the SP: #{expected}")
    end

    private def valid_issuer? : Bool
      idp_entity_id = settings.try(&.idp_entity_id)
      value = issuer
      return true if idp_entity_id.nil? || value.nil?

      unless Utils.uri_match?(value, idp_entity_id)
        return append_error("Doesn't match the issuer, expected: <#{idp_entity_id}>, but was: <#{value}>")
      end
      true
    end

    private def validate_signature : Bool
      current = settings
      return true unless current

      case result = check_redirect_signature("SAMLResponse", current, options)
      when nil, true then true
      when String    then append_error(result)
      else                append_error("Invalid Signature on Logout Response")
      end
    end
  end
end
