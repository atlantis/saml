# Only supports SAML 2.0
module Saml

  # SAML2 Logout Request (SLO IdP initiated, Parser)
  #
  class SloLogoutrequest < SamlMessage
    include ErrorHandling

    # Saml::Settings Toolkit settings
    property :settings

    getter :document
    getter :request
    getter :options

    property :soft

    @name_id : String?
    @name_id_format : String?
    @issuer : String?
    @not_on_or_after : Time?
    @uuid : String?

    # Constructs the Logout Request. A Logout Request Object that is an extension of the SamlMessage class.
    # @param request [String] A UUEncoded Logout Request from the IdP.
    # @param options [Hash]  :settings to provide the Saml::Settings object
    #                        Or :allowed_clock_drift for the logout request validation process to allow a clock drift when checking dates with
    #                        Or :relax_signature_validation to accept signatures if no idp certificate registered on settings
    #
    # @raise [ArgumentError] If Request is nil
    #
    def initialize(request, options = {} of Symbol => String)
      raise ArgumentError.new("Request cannot be nil") if request.nil?

      @error_messages = [] of String
      @options = options
      @soft = true
      unless options[:settings].nil?
        @settings = options[:settings]
        unless @settings.soft.nil?
          @soft = @settings.soft
        end
      end

      @request = decode_raw_saml(request, settings)
      @document = REXML::Document.new(@request)
    end

    def request_id
      id(document)
    end

    # Validates the Logout Request with the default values (soft = true)
    # @param collect_errors [Boolean] Stop validation when first error appears or keep validating.
    # @return [Boolean] TRUE if the Logout Request is valid
    #
    def is_valid?(collect_errors = false)
      validate(collect_errors)
    end

    # @return [String] Gets the NameID of the Logout Request.
    #
    def name_id
      @name_id ||= begin
        node = document.xpath_node("/p:LogoutRequest/a:NameID", { "p" => PROTOCOL, "a" => ASSERTION })
        Utils.element_text(node)
      end
    end

    def nameid
      self.name_id
    end

    # @return [String] Gets the NameID Format of the Logout Request.
    #
    def name_id_format
      @name_id_node ||= document.xpath_node("/p:LogoutRequest/a:NameID", { "p" => PROTOCOL, "a" => ASSERTION })
      @name_id_format ||=
        if @name_id_node && @name_id_node.attribute("Format")
          @name_id_node.attribute("Format").value
        end
    end

    def nameid_format
      self.name_id_format
    end

    # @return [String|nil] Gets the ID attribute from the Logout Request. if exists.
    #
    def id
      super(document)
    end

    # @return [String] Gets the Issuer from the Logout Request.
    #
    def issuer
      @issuer ||= begin
        node = document.xpath_node(
          "/p:LogoutRequest/a:Issuer",
          { "p" => PROTOCOL, "a" => ASSERTION }
        )
        Utils.element_text(node)
      end
    end

    # @return [Time|nil] Gets the NotOnOrAfter Attribute value if exists.
    #
    def not_on_or_after
      @not_on_or_after ||= begin
        node = document.xpath_node(
          "/p:LogoutRequest",
          { "p" => PROTOCOL }
        )
        if node && node.attributes["NotOnOrAfter"]
          Time.parse(node.attributes["NotOnOrAfter"])
        end
      end
    end

    # @return [Array] Gets the SessionIndex if exists (Supported multiple values). Empty Array if none found
    #
    def session_indexes
      nodes = document.xpath_nodes(
        "/p:LogoutRequest/p:SessionIndex",
        { "p" => PROTOCOL }
      )

      nodes.map { |node| Utils.element_text(node) }
    end

    # returns the allowed clock drift on timing validation
    # @return [Float]
    private def allowed_clock_drift
      options[:allowed_clock_drift].to_f.abs + Float::EPSILON
    end

    # Hard aux function to validate the Logout Request
    # @param collect_errors [Boolean] Stop validation when first error appears or keep validating. (if soft=true)
    # @return [Boolean] TRUE if the Logout Request is valid
    # @raise [ValidationError] if soft == false and validation fails
    #
    private def validate(collect_errors = false)
      reset_errors!

      validations = [
        :validate_request_state,
        :validate_id,
        :validate_version,
        :validate_structure,
        :validate_not_on_or_after,
        :validate_issuer,
        :validate_signature,
      ]

      if collect_errors
        validations.each { |validation| send(validation) }
        @error_messages.empty?
      else
        validations.all? { |validation| send(validation) }
      end
    end

    # Validates that the Logout Request contains an ID
    # If fails, the error is added to the errors array.
    # @return [Boolean] True if the Logout Request contains an ID, otherwise returns False
    #
    private def validate_id
      unless id
        return append_error("Missing ID attribute on Logout Request")
      end

      true
    end

    # Validates the SAML version (2.0)
    # If fails, the error is added to the errors array.
    # @return [Boolean] True if the Logout Request is 2.0, otherwise returns False
    #
    private def validate_version
      unless version(document) == "2.0"
        return append_error("Unsupported SAML version")
      end

      true
    end

    # Validates the time. (If the logout request was initialized with the :allowed_clock_drift
    # option, the timing validations are relaxed by the allowed_clock_drift value)
    # If fails, the error is added to the errors array
    # @return [Boolean] True if satisfies the conditions, otherwise False if soft=True
    # @raise [ValidationError] if soft == false and validation fails
    #
    private def validate_not_on_or_after
      now = Time.utc

      if not_on_or_after && now >= (not_on_or_after + allowed_clock_drift)
        return append_error("Current time is on or after NotOnOrAfter (#{now} >= #{not_on_or_after}#{" + #{allowed_clock_drift.ceil}s" if allowed_clock_drift > 0})")
      end

      true
    end

    # Validates the Logout Request against the specified schema.
    # @return [Boolean] True if the XML is valid, otherwise False if soft=True
    # @raise [ValidationError] if soft == false and validation fails
    #
    private def validate_structure
      unless valid_saml?(document, soft)
        return append_error("Invalid SAML Logout Request. Not match the saml-schema-protocol-2.0.xsd")
      end

      true
    end

    # Validates that the Logout Request provided in the initialization is not empty,
    # @return [Boolean] True if the required info is found, otherwise False if soft=True
    # @raise [ValidationError] if soft == false and validation fails
    #
    private def validate_request_state
      return append_error("Blank logout request") if request.nil? || request.empty?

      true
    end

    # Validates the Issuer of the Logout Request
    # If fails, the error is added to the errors array
    # @return [Boolean] True if the Issuer matchs the IdP entityId, otherwise False if soft=True
    # @raise [ValidationError] if soft == false and validation fails
    #
    private def validate_issuer
      return true if settings.nil? || settings.idp_entity_id.nil? || issuer.nil?

      unless Saml::Utils.uri_match?(issuer, settings.idp_entity_id.not_nil!)
        return append_error("Doesn't match the issuer, expected: <#{settings.idp_entity_id}>, but was: <#{issuer}>")
      end

      true
    end

    # Validates the Signature if exists and GET parameters are provided
    # @return [Boolean] True if not contains a Signature or if the Signature is valid, otherwise False if soft=True
    # @raise [ValidationError] if soft == false and validation fails
    #
    private def validate_signature
      return true if options.nil?
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
        type: "SAMLRequest",
        raw_data: options[:raw_get_params]["SAMLRequest"],
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
        return append_error("Invalid Signature on Logout Request")
      end

      true
    end
  end
end
