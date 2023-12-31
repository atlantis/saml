# Only supports SAML 2.0
module Saml

  # SAML2 Logout Response (SLO IdP initiated, Parser)
  #
  class Logoutresponse < SamlMessage
    include ErrorHandling

    # Saml::Settings Toolkit settings
    property :settings

    getter :document
    getter :response
    getter :options

    property :soft

    @in_response_to : String?
    @issuer : String?
    @status_code : String?
    @status_message : String?
    @name_id : String?

    # Constructs the Logout Response. A Logout Response Object that is an extension of the SamlMessage class.
    # @param response  [String] A UUEncoded logout response from the IdP.
    # @param settings  [::Settings|nil] Toolkit settings
    # @param options   [Hash] Extra parameters.
    #                    :matches_request_id It will validate that the logout response matches the ID of the request.
    #                    :get_params GET Parameters, including the SAMLResponse
    #                    :relax_signature_validation to accept signatures if no idp certificate registered on settings
    #
    # @raise [ArgumentError] if response is nil
    #
    def initialize(response, settings : Settings? = nil, options = {} of Symbol => String )
      @error_messages = [] of String
      raise ArgumentError.new("Logoutresponse cannot be nil") if response.nil?
      @settings = settings

      if settings.nil? || settings.soft.nil?
        @soft = true
      else
        @soft = settings.soft
      end

      @options = options
      @response = decode_raw_saml(response, settings)
      @document = XMLSecurity::SignedDocument.new(@response)
    end

    def response_id
      id(document)
    end

    # Checks if the Status has the "Success" code
    # @return [Boolean] True if the StatusCode is Sucess
    # @raise [ValidationError] if soft == false and validation fails
    #
    def success?
      return status_code == "urn:oasis:names:tc:SAML:2.0:status:Success"
    end

    # @return [String|nil] Gets the InResponseTo attribute from the Logout Response if exists.
    #
    def in_response_to
      @in_response_to ||= begin
        node = document.xpath_node(
          "/p:LogoutResponse",
          { "p" => PROTOCOL }
        )
        if n = node
          n["InResponseTo"]?
        else
          nil
        end
      end
    end

    # @return [String] Gets the Issuer from the Logout Response.
    #
    def issuer
      @issuer ||= begin
        node = document.xpath_node(
          "/p:LogoutResponse/a:Issuer",
          { "p" => PROTOCOL, "a" => ASSERTION }
        )
        Utils.element_text(node)
      end
    end

    # @return [String] Gets the StatusCode from a Logout Response.
    #
    def status_code
      @status_code ||= begin
        if node = document.xpath_node(
            "/p:LogoutResponse/p:Status/p:StatusCode",
            { "p" => PROTOCOL }
          )
          node["Value"]
        end
      end
    end

    def status_message
      @status_message ||= begin
        if node = document.xpath_node(
            "/p:LogoutResponse/p:Status/p:StatusMessage",
            { "p" => PROTOCOL }
          )
          Utils.element_text(node)
        end
      end
    end

    # Aux function to validate the Logout Response
    # @param collect_errors [Boolean] Stop validation when first error appears or keep validating. (if soft=true)
    # @return [Boolean] TRUE if the SAML Response is valid
    # @raise [ValidationError] if soft == false and validation fails
    #
    def validate(collect_errors = false)
      reset_errors!

      validations = [
        :valid_state?,
        :validate_success_status,
        :validate_structure,
        :valid_in_response_to?,
        :valid_issuer?,
        :validate_signature,
      ]

      if collect_errors
        validations.each { |validation| send(validation) }
        @error_messages.empty?
      else
        validations.all? { |validation| send(validation) }
      end
    end

    # Validates the Status of the Logout Response
    # If fails, the error is added to the errors array, including the StatusCode returned and the Status Message.
    # @return [Boolean] True if the Logout Response contains a Success code, otherwise False if soft=True
    # @raise [ValidationError] if soft == false and validation fails
    #
    private def validate_success_status
      return true if success?

      error_msg = "The status code of the Logout Response was not Success"
      status_error_msg = Saml::Utils.status_error_msg(error_msg, status_code, status_message)
      append_error(status_error_msg)
    end

    # Validates the Logout Response against the specified schema.
    # @return [Boolean] True if the XML is valid, otherwise False if soft=True
    # @raise [ValidationError] if soft == false and validation fails
    #
    private def validate_structure
      unless valid_saml?(document, soft)
        return append_error("Invalid SAML Logout Response. Not match the saml-schema-protocol-2.0.xsd")
      end

      true
    end

    # Validates that the Logout Response provided in the initialization is not empty,
    # also check that the setting and the IdP cert were also provided
    # @return [Boolean] True if the required info is found, otherwise False if soft=True
    # @raise [ValidationError] if soft == false and validation fails
    #
    private def valid_state?
      return append_error("Blank logout response") if response.empty?

      return append_error("No settings on logout response") if settings.nil?

      return append_error("No sp_entity_id in settings of the logout response") if settings.sp_entity_id.nil?

      if settings.idp_cert_fingerprint.nil? && settings.idp_cert.nil? && settings.idp_cert_multi.nil?
        return append_error("No fingerprint or certificate on settings of the logout response")
      end

      true
    end

    # Validates if a provided :matches_request_id matchs the inResponseTo value.
    # @param soft [String|nil] request_id The ID of the Logout Request sent by this SP to the IdP (if was sent any)
    # @return [Boolean] True if there is no request_id or it match, otherwise False if soft=True
    # @raise [ValidationError] if soft == false and validation fails
    #
    private def valid_in_response_to?
      return true unless options.has_key? :matches_request_id
      return true if options[:matches_request_id].nil?
      return true unless options[:matches_request_id] != in_response_to

      error_msg = "The InResponseTo of the Logout Response: #{in_response_to}, does not match the ID of the Logout Request sent by the SP: #{options[:matches_request_id]}"
      append_error(error_msg)
    end

    # Validates the Issuer of the Logout Response
    # @return [Boolean] True if the Issuer matchs the IdP entityId, otherwise False if soft=True
    # @raise [ValidationError] if soft == false and validation fails
    #
    private def valid_issuer?
      return true if settings.idp_entity_id.nil? || issuer.nil?

      unless Saml::Utils.uri_match?(issuer, settings.idp_entity_id.not_nil!)
        return append_error("Doesn't match the issuer, expected: <#{settings.idp_entity_id}>, but was: <#{issuer}>")
      end
      true
    end

    # Validates the Signature if it exists and the GET parameters are provided
    # @return [Boolean] True if not contains a Signature or if the Signature is valid, otherwise False if soft=True
    # @raise [ValidationError] if soft == false and validation fails
    #
    private def validate_signature
      return true unless !options.nil?
      return true unless options.has_key? :get_params
      return true unless options[:get_params].has_key? "Signature"

      options[:raw_get_params] = Saml::Utils.prepare_raw_get_params(options[:raw_get_params], options[:get_params], settings.security[:lowercase_url_encoding])

      if options[:get_params]["SigAlg"].nil? && !options[:raw_get_params]["SigAlg"].nil?
        options[:get_params]["SigAlg"] = URL.decode(options[:raw_get_params]["SigAlg"])
      end

      idp_cert = settings.get_idp_cert
      idp_certs = settings.get_idp_cert_multi

      if idp_cert.nil? && (idp_certs.nil? || idp_certs[:signing].empty?)
        return options.has_key? :relax_signature_validation
      end

      query_string = Saml::Utils.build_query_from_raw_parts(
        type: "SAMLResponse",
        raw_data: options[:raw_get_params]["SAMLResponse"],
        raw_relay_state: options[:raw_get_params]["RelayState"],
        raw_sig_alg: options[:raw_get_params]["SigAlg"],
      )

      expired = false
      if idp_certs.nil? || idp_certs[:signing].empty?
        valid = Saml::Utils.verify_signature(
          cert: idp_cert,
          sig_alg: options[:get_params]["SigAlg"],
          signature: options[:get_params]["Signature"],
          query_string: query_string,
        )
        if valid && settings.security[:check_idp_cert_expiration]?
          if Saml::Utils.is_cert_expired(idp_cert)
            expired = true
          end
        end
      else
        valid = false
        idp_certs[:signing].each do |signing_idp_cert|
          valid = Saml::Utils.verify_signature(
            cert: signing_idp_cert,
            sig_alg: options[:get_params]["SigAlg"],
            signature: options[:get_params]["Signature"],
            query_string: query_string,
          )
          if valid
            if settings.security[:check_idp_cert_expiration]?
              if Saml::Utils.is_cert_expired(signing_idp_cert)
                expired = true
              end
            end
            break
          end
        end
      end

      if expired
        error_msg = "IdP x509 certificate expired"
        return append_error(error_msg)
      end
      unless valid
        error_msg = "Invalid Signature on Logout Response"
        return append_error(error_msg)
      end
      true
    end
  end
end
