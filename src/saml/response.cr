# Only supports SAML 2.0
module Saml

  # SAML2 Authentication Response. SAML Response
  #
  class Response < SamlMessage
    alias OptionValue = String | Bool | Float32 | Float64 | Int32 | Int64 | Time::Span | Settings | Symbol
    include ErrorHandling

    ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion"
    PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol"
    DSIG = "http://www.w3.org/2000/09/xmldsig#"
    XENC = "http://www.w3.org/2001/04/xmlenc#"

    # TODO: Settings should probably be initialized too... WDYT?

    # Saml::Settings Toolkit settings
    property settings : Saml::Settings

    getter document : XMLSecurity::SignedDocument
    getter decrypted_document : XMLSecurity::SignedDocument? = nil
    getter :response
    property options : Hash(Symbol, OptionValue)

    property :soft

    @name_id : String?
    @name_id_format : String?
    @name_id_node : XML::Node?
    @name_id_spnamequalifier : String?
    @name_id_namequalifier : String?
    @sessionindex : String?
    @expires_at : Time?
    @status_code : String?
    @status_message : String?
    @in_response_to : String?
    @destination : String?
    @assertion_id : String?
    @soft : Bool = true
    @response : String
    @attr_statements : Saml::Attributes?
    @conditions : XML::Node?
    @not_before : Time?
    @not_on_or_after : Time?
    @audiences : Array(String)? = nil
    @issuers : Array(String)? = nil

    # Response available options
    # This is not a whitelist to allow people extending Saml:Response
    # and pass custom options
    AVAILABLE_OPTIONS = [
      :allowed_clock_drift, :check_duplicated_attributes, :matches_request_id, :settings, :skip_audience, :skip_authnstatement, :skip_conditions,
      :skip_destination, :skip_recipient_check, :skip_subject_confirmation,
    ]
    # TODO: Update the comment on initialize to describe every option

    # Constructs the SAML Response. A Response Object that is an extension of the SamlMessage class.
    # @param response [String] A UUEncoded SAML response from the IdP.
    # @param options  [Hash]   :settings to provide the Saml::Settings object
    #                          Or some options for the response validation process like skip the conditions validation
    #                          with the :skip_conditions, or allow a clock_drift when checking dates with :allowed_clock_drift
    #                          or :matches_request_id that will validate that the response matches the ID of the request,
    #                          or skip the subject confirmation validation with the :skip_subject_confirmation option
    #                          or skip the recipient validation of the subject confirmation element with :skip_recipient_check option
    #                          or skip the audience validation with :skip_audience option
    #
    def initialize(response : String?, options = {} of Symbol => OptionValue)
      @options = options.merge({} of Symbol => OptionValue)
      @settings = @options[:settings]?.as?(Saml::Settings) || Saml::Settings.new
      @error_messages = [] of String

      @soft = true
      if settings = @settings
        unless settings.soft.nil?
          @soft = settings.soft
        end
      end

      response = response && !response.empty? ? response : "<blank></blank>"
      @response = decode_raw_saml(response, @settings)
      @document = XMLSecurity::SignedDocument.new(@response, @error_messages)

      if assertion_encrypted?
        @decrypted_document = generate_decrypted_document
      end
    end

    def errors : Array(String)
      @error_messages
    end

    # Validates the SAML Response with the default values (soft = true)
    # @param collect_errors [Boolean] Stop validation when first error appears or keep validating. (if soft=true)
    # @return [Boolean] TRUE if the SAML Response is valid
    #
    def is_valid?(collect_errors = false)
      validate(collect_errors)
    end

    # @return [String] the NameID provided by the SAML response from the IdP.
    #
    def name_id
      @name_id ||= Utils.element_text(name_id_node)
    end

    def nameid
      self.name_id
    end

    # @return [String] the NameID Format provided by the SAML response from the IdP.
    #
    def name_id_format
      @name_id_format ||=
        if node = name_id_node
          node["Format"]
        end
    end

    def nameid_format
      self.name_id_format
    end

    # @return [String] the NameID SPNameQualifier provided by the SAML response from the IdP.
    #
    def name_id_spnamequalifier
      @name_id_spnamequalifier ||=
        if node = name_id_node
          node["SPNameQualifier"]?
        end
    end

    # @return [String] the NameID NameQualifier provided by the SAML response from the IdP.
    #
    def name_id_namequalifier
      @name_id_namequalifier ||=
        if node = name_id_node
          node["NameQualifier"]
        end
    end

    # Gets the SessionIndex from the AuthnStatement.
    # Could be used to be stored in the local session in order
    # to be used in a future Logout Request that the SP could
    # send to the IdP, to set what specific session must be deleted
    # @return [String] SessionIndex Value
    #
    def sessionindex
      @sessionindex ||= begin
        if node = xpath_first_from_signed_assertion("/a:AuthnStatement")
          node["SessionIndex"]
        end
      end
    end

    # Gets the Attributes from the AttributeStatement element.
    #
    # All attributes can be iterated over +attributes.each+ or returned as array by +attributes.all+
    # For backwards compatibility ruby-saml returns by default only the first value for a given attribute with
    #    attributes['name']
    # To get all of the attributes, use:
    #    attributes.multi('name')
    # Or turn off the compatibility:
    #    Saml::Attributes.single_value_compatibility = false
    # Now this will return an array:
    #    attributes['name']
    #
    # @return [Attributes] Saml::Attributes enumerable collection.
    # @raise [ValidationError] if there are 2+ Attribute with the same Name
    #
    def attributes
      @attr_statements ||= begin
        attributes = Attributes.new

        if stmt_elements = xpath_from_signed_assertion("/a:AttributeStatement")
          stmt_elements.each do |stmt_element|
            stmt_element.children.each do |attr_element|
              next unless attr_element.element?

              if attr_element.name == "EncryptedAttribute"
                node = decrypt_attribute(attr_element.dup)
              else
                node = attr_element
              end

              if node && (name = node["Name"]?)
                if options[:check_duplicated_attributes]? && attributes.includes?(name)
                  raise ValidationError.new("Found an Attribute element with duplicated Name")
                end

                values = node.children.select{|e| e.element? }.map do |e|
                  # if we don't have any child element nodes
                  if e.xpath_nodes("./*").empty?
                    # SAMLCore requires that nil AttributeValues MUST contain xsi:nil XML attribute set to "true" or "1"
                    # otherwise the value is to be regarded as empty.
                    ["true", "1"].includes?(e["xsi:nil"]?) ? nil : Utils.element_text(e)
                    # explicitly support saml2:NameID with saml2:NameQualifier if supplied in attributes
                    # this is useful for allowing eduPersonTargetedId to be passed as an opaque identifier to use to
                    # identify the subject in an SP rather than email or other less opaque attributes
                    # NameQualifier, if present is prefixed with a "/" to the value
                  else
                    e.xpath_nodes("a:NameID", { "a" => ASSERTION }).map do |n|
                      base_path = n["NameQualifier"]? ? "#{n["NameQualifier"]}/" : ""
                      "#{base_path}#{Utils.element_text(n)}"
                    end
                  end
                end
              else
                puts "INALID STATMENT: #{stmt_element.inspect}"
                raise ValidationError.new("Found an Attribute element with no Name")
              end

              attributes.add(name, values.flatten)
            end
          end
        end
        attributes
      end
    end

    # Gets the SessionNotOnOrAfter from the AuthnStatement.
    # Could be used to set the local session expiration (expire at latest)
    # @return [String] The SessionNotOnOrAfter value
    #
    def session_expires_at
      @expires_at ||= begin
        if node = xpath_first_from_signed_assertion("/a:AuthnStatement")
          parse_time(node, "SessionNotOnOrAfter")
        end
      end
    end

    # Checks if the Status has the "Success" code
    # @return [Boolean] True if the StatusCode is Sucess
    #
    def success?
      status_code == "urn:oasis:names:tc:SAML:2.0:status:Success"
    end

    # @return [String] StatusCode value from a SAML Response.
    #
    def status_code
      @status_code ||= begin
        nodes = document.xpath_nodes(
          "/p:Response/p:Status/p:StatusCode",
          { "p" => PROTOCOL }
        )
        if nodes.size == 1
          node = nodes[0]
          code = node["Value"] if node

          unless code == "urn:oasis:names:tc:SAML:2.0:status:Success"
            nodes = document.xpath_nodes(
              "/p:Response/p:Status/p:StatusCode/p:StatusCode",
              { "p" => PROTOCOL }
            )
            statuses = nodes.map do |inner_node|
              inner_node["Value"]
            end

            code = [code, statuses].flatten.join(" | ")
          end

          code
        end
      end
    end

    # @return [String] the StatusMessage value from a SAML Response.
    #
    def status_message
      @status_message ||= begin
        nodes = document.xpath_nodes(
          "/p:Response/p:Status/p:StatusMessage",
          { "p" => PROTOCOL }
        )
        if nodes.size == 1
          Utils.element_text(nodes.first)
        end
      end
    end

    # Gets the Condition Element of the SAML Response if exists.
    # (returns the first node that matches the supplied xpath)
    # @return [XML::Node] Conditions Element if exists
    #
    def conditions
      @conditions ||= xpath_first_from_signed_assertion("/a:Conditions")
    end

    # Gets the NotBefore Condition Element value.
    # @return [Time] The NotBefore value in Time format
    #
    def not_before
      @not_before ||= parse_time(conditions, "NotBefore")
    end

    # Gets the NotOnOrAfter Condition Element value.
    # @return [Time] The NotOnOrAfter value in Time format
    #
    def not_on_or_after
      @not_on_or_after ||= parse_time(conditions, "NotOnOrAfter")
    end

    # Gets the Issuers (from Response and Assertion).
    # (returns the first node that matches the supplied xpath from the Response and from the Assertion)
    # @return [Array] Array with the Issuers (XML::Node)
    #
    def issuers
      @issuers ||= begin
        issuer_response_nodes = document.xpath_nodes(
          "/p:Response/a:Issuer",
          { "p" => PROTOCOL, "a" => ASSERTION }
        )

        unless issuer_response_nodes.size == 1
          error_msg = "Issuer of the Response not found or multiple."
          raise ValidationError.new(error_msg)
        end

        issuer_assertion_nodes = xpath_from_signed_assertion("/a:Issuer")
        unless issuer_assertion_nodes.try(&.size) == 1
          error_msg = "Issuer of the Assertion not found or multiple."
          raise ValidationError.new(error_msg)
        end

        issuer_strings = [] of String?

        issuer_response_nodes.each do |node|
          issuer_strings << Utils.element_text(node)
        end

        issuer_assertion_nodes.not_nil!.each do |node|
          issuer_strings << Utils.element_text(node)
        end

        issuer_strings.compact.uniq
      end
    end

    # @return [String|nil] The InResponseTo attribute from the SAML Response.
    #
    def in_response_to
      @in_response_to ||= begin
        node = document.xpath_node(
          "/p:Response",
          { "p" => PROTOCOL }
        )
        if n = node
          n["InResponseTo"]?
        end
      end
    end

    # @return [String|nil] Destination attribute from the SAML Response.
    #
    def destination
      @destination ||= begin
        node = document.xpath_node(
          "/p:Response",
          { "p" => PROTOCOL }
        )
        if n = node
          n["Destination"]?
        end
      end
    end

    # @return [Array] The Audience elements from the Contitions of the SAML Response.
    #
    def audiences
      @audiences ||= begin
        if nodes = xpath_from_signed_assertion("/a:Conditions/a:AudienceRestriction/a:Audience")
          nodes.map { |node| Utils.element_text(node) }.compact.reject(&.empty?)
        else
          [] of String
        end
      end
    end

    # returns the allowed clock drift on timing validation
    # @return [Float]
    def allowed_clock_drift
      if drift = options[:allowed_clock_drift]?.as?(Int32 | Float32)
        Time::Span.new(nanoseconds: ((drift.to_f.abs + Float32::EPSILON) * 1000000000).round.to_i)
      else
        Time::Span.new(seconds: 1)
      end
    end

    # Checks if the SAML Response contains or not an EncryptedAssertion element
    # @return [Boolean] True if the SAML Response contains an EncryptedAssertion element
    #
    def assertion_encrypted?
      !document.xpath_node(
        "(/samlp:Response/EncryptedAssertion)|(/samlp:Response/a:EncryptedAssertion)",
        { "samlp" => PROTOCOL, "a" => ASSERTION }
      ).nil?
    end

    def response_id
      id(document)
    end

    def assertion_id
      @assertion_id ||= begin
        if node = xpath_first_from_signed_assertion("")
          node["ID"]?
        end
      end
    end

    # Validates the SAML Response (calls several validation methods)
    # @param collect_errors [Boolean] Stop validation when first error appears or keep validating. (if soft=true)
    # @return [Boolean] True if the SAML Response is valid, otherwise False if soft=True
    # @raise [ValidationError] if soft == false and validation fails
    #
    private def validate(collect_errors = false)
      reset_errors!
      return false unless validate_response_state

      validations = [
        ->{ self.validate_version },
        ->{ self.validate_id },
        ->{ self.validate_success_status },
        ->{ self.validate_num_assertion },
        ->{ self.validate_no_duplicated_attributes },
        ->{ self.validate_signed_elements },
        ->{ self.validate_structure },
        ->{ self.validate_in_response_to },
        ->{ self.validate_one_conditions },
        ->{ self.validate_conditions },
        ->{ self.validate_one_authnstatement },
        ->{ self.validate_audience },
        ->{ self.validate_destination },
        ->{ self.validate_issuer },
        ->{ self.validate_session_expiration },
        ->{ self.validate_subject_confirmation },
        -> { self.validate_name_id },
        ->{ self.validate_signature },
      ]

      if collect_errors
        validations.each { |validation| validation.call }
        @error_messages.empty?
      else
        validations.each do |validation|
          return false unless validation.call == true
        end

        true
      end
    end

    # Validates the Status of the SAML Response
    # @return [Boolean] True if the SAML Response contains a Success code, otherwise False if soft == false
    # @raise [ValidationError] if soft == false and validation fails
    #
    private def validate_success_status
      return true if success?

      error_msg = "The status code of the Response was not Success"
      status_error_msg = Saml::Utils.status_error_msg(error_msg, status_code, status_message)
      append_error(status_error_msg)
    end

    # Validates the SAML Response against the specified schema.
    # @return [Boolean] True if the XML is valid, otherwise False if soft=True
    # @raise [ValidationError] if soft == false and validation fails
    #
    private def validate_structure
      structure_error_msg = "Invalid SAML Response. Not match the saml-schema-protocol-2.0.xsd"
      unless valid_saml?(document, soft)
        return append_error(structure_error_msg)
      end

      unless decrypted_document.nil?
        unless valid_saml?(decrypted_document, soft)
          return append_error(structure_error_msg)
        end
      end

      true
    end

    # Validates that the SAML Response provided in the initialization is not empty,
    # also check that the setting and the IdP cert were also provided
    # @return [Boolean] True if the required info is found, false otherwise
    #
    private def validate_response_state
      return append_error("Blank response") if response.empty? || response == "<blank></blank>"

      return append_error("No settings on response") if settings.nil?

      if settings.idp_cert_fingerprint.nil? && settings.idp_cert.nil? && settings.idp_cert_multi.nil?
        return append_error("No fingerprint or certificate on settings")
      end

      true
    end

    # Validates that the SAML Response contains an ID
    # If fails, the error is added to the errors array.
    # @return [Boolean] True if the SAML Response contains an ID, otherwise returns False
    #
    private def validate_id
      unless response_id
        return append_error("Missing ID attribute on SAML Response")
      end

      true
    end

    # Validates the SAML version (2.0)
    # If fails, the error is added to the errors array.
    # @return [Boolean] True if the SAML Response is 2.0, otherwise returns False
    #
    private def validate_version
      unless version(document) == "2.0"
        return append_error("Unsupported SAML version")
      end

      true
    end

    # Validates that the SAML Response only contains a single Assertion (encrypted or not).
    # If fails, the error is added to the errors array.
    # @return [Boolean] True if the SAML Response contains one unique Assertion, otherwise False
    #
    private def validate_num_assertion
      error_msg = "SAML Response must contain 1 assertion"
      assertions = document.xpath_nodes(
        "//a:Assertion",
        { "a" => ASSERTION }
      )
      encrypted_assertions = document.xpath_nodes(
        "//a:EncryptedAssertion",
        { "a" => ASSERTION }
      )

      unless assertions.size + encrypted_assertions.size == 1
        return append_error(error_msg)
      end

      unless decrypted_document.nil?
        if ddoc = decrypted_document
          assertions = ddoc.xpath_nodes(
            "//a:Assertion",
            { "a" => ASSERTION }
          )
          unless assertions.size == 1
            return append_error(error_msg)
          end
        else
          return append_error("No decrypted document to check num assertions")
        end
      end

      true
    end

    # Validates that there are not duplicated attributes
    # If fails, the error is added to the errors array
    # @return [Boolean] True if there are no duplicated attribute elements, otherwise False if soft=True
    # @raise [ValidationError] if soft == false and validation fails
    #
    private def validate_no_duplicated_attributes
      if options[:check_duplicated_attributes]?
        begin
          attributes
        rescue e : ValidationError
          return append_error(e.message || "Unknown error in duplicate attributes check")
        end
      end

      true
    end

    # Validates the Signed elements
    # If fails, the error is added to the errors array
    # @return [Boolean] True if there is 1 or 2 Elements signed in the SAML Response
    #                                   an are a Response or an Assertion Element, otherwise False if soft=True
    #
    private def validate_signed_elements
      if doc = decrypted_document || document
        signature_nodes = doc.xpath_nodes(
          "//ds:Signature",
          { "ds" => DSIG }
        )
        signed_elements = [] of String
        verified_seis = [] of String
        verified_ids = [] of String
        signature_nodes.each do |signature_node|
          signed_element = signature_node.parent.try(&.name)
          if signed_element != "Response" && signed_element != "Assertion"
            return append_error("Invalid Signature Element '#{signed_element}'. SAML Response rejected")
          end

          if parent = signature_node.parent
            if parent["ID"]?.nil?
              return append_error("Signed Element must contain an ID. SAML Response rejected")
            end

            id = parent["ID"]
            if verified_ids.includes?(id)
              return append_error("Duplicated ID. SAML Response rejected")
            end
            verified_ids.push(id)
          end

          # Check that reference URI matches the parent ID and no duplicate References or IDs
          ref = signature_node.xpath_node(".//ds:Reference", { "ds" => DSIG })
          if ref

            if (uri = ref["URI"]?) && !uri.empty?
              sei = uri[1..-1]

              unless sei == id
                return append_error("Found an invalid Signed Element. SAML Response rejected")
              end

              if verified_seis.includes?(sei)
                return append_error("Duplicated Reference URI. SAML Response rejected")
              end

              verified_seis.push(sei)
            end
          end

          signed_elements << signed_element if signed_element
        end

        unless signature_nodes.size < 3 && !signed_elements.empty?
          return append_error("Found an unexpected number of Signature Element. SAML Response rejected")
        end

        if settings.security[:want_assertions_signed]? && !(signed_elements.includes? "Assertion")
          return append_error("The Assertion of the Response is not signed and the SP requires it")
        end
      else
        return append_error("No document to validate_signed_elements")
      end

      true
    end

    # Validates if the provided request_id match the inResponseTo value.
    # If fails, the error is added to the errors array
    # @return [Boolean] True if there is no request_id or it match, otherwise False if soft=True
    # @raise [ValidationError] if soft == false and validation fails
    #
    private def validate_in_response_to
      return true unless options.has_key? :matches_request_id
      return true if options[:matches_request_id].nil?
      return true unless options[:matches_request_id] != in_response_to

      error_msg = "The InResponseTo of the Response: #{in_response_to}, does not match the ID of the AuthNRequest sent by the SP: #{options[:matches_request_id]}"
      append_error(error_msg)
    end

    # Validates the Audience, (If the Audience match the Service Provider EntityID)
    # If the response was initialized with the :skip_audience option, this validation is skipped,
    # If fails, the error is added to the errors array
    # @return [Boolean] True if there is an Audience Element that match the Service Provider EntityID, otherwise False if soft=True
    # @raise [ValidationError] if soft == false and validation fails
    #
    private def validate_audience
      return true if options[:skip_audience]?
      return true if settings.sp_entity_id.nil? || settings.sp_entity_id.not_nil!.empty?

      if audiences.empty?
        return true unless settings.security[:strict_audience_validation]?
        return append_error("Invalid Audiences. The <AudienceRestriction> element contained only empty <Audience> elements. Expected audience #{settings.sp_entity_id}.")
      end

      unless audiences.includes? settings.sp_entity_id
        s = audiences.size > 1 ? "s" : ""
        error_msg = "Invalid Audience#{s}. The audience#{s} #{audiences.join(",")}, did not match the expected audience #{settings.sp_entity_id}"
        return append_error(error_msg)
      end

      true
    end

    # Validates the Destination, (If the SAML Response is received where expected).
    # If the response was initialized with the :skip_destination option, this validation is skipped,
    # If fails, the error is added to the errors array
    # @return [Boolean] True if there is a Destination element that matches the Consumer Service URL, otherwise False
    #
    private def validate_destination
      return true if destination.nil?
      return true if options[:skip_destination]?

      if destination.nil? || destination.not_nil!.empty?
        error_msg = "The response has an empty Destination value"
        return append_error(error_msg)
      end

      return true if settings.assertion_consumer_service_url.nil? || settings.assertion_consumer_service_url.not_nil!.empty?

      unless destination && Saml::Utils.uri_match?(destination.not_nil!, settings.assertion_consumer_service_url.not_nil!)
        error_msg = "The response was received at #{destination} instead of #{settings.assertion_consumer_service_url}"
        return append_error(error_msg)
      end

      true
    end

    # Checks that the samlp:Response/saml:Assertion/saml:Conditions element exists and is unique.
    # (If the response was initialized with the :skip_conditions option, this validation is skipped)
    # If fails, the error is added to the errors array
    # @return [Boolean] True if there is a conditions element and is unique
    #
    private def validate_one_conditions
      puts "OPTIOS: #{options.inspect}"
      return true if options[:skip_conditions]?

      conditions_nodes = xpath_from_signed_assertion("/a:Conditions") || [] of XML::NodeSet
      unless conditions_nodes.size == 1
        error_msg = "The Assertion must include one Conditions element"
        return append_error(error_msg)
      end

      true
    end

    # Checks that the samlp:Response/saml:Assertion/saml:AuthnStatement element exists and is unique.
    # If fails, the error is added to the errors array
    # @return [Boolean] True if there is a authnstatement element and is unique
    #
    private def validate_one_authnstatement
      return true if options[:skip_authnstatement]?

      authnstatement_nodes = xpath_from_signed_assertion("/a:AuthnStatement") || [] of XML::Node
      unless authnstatement_nodes.size == 1
        error_msg = "The Assertion must include one AuthnStatement element"
        return append_error(error_msg)
      end

      true
    end

    # Validates the Conditions. (If the response was initialized with the :skip_conditions option, this validation is skipped,
    # If the response was initialized with the :allowed_clock_drift option, the timing validations are relaxed by the allowed_clock_drift value)
    # @return [Boolean] True if satisfies the conditions, otherwise False if soft=True
    # @raise [ValidationError] if soft == false and validation fails
    #
    private def validate_conditions
      return true if conditions.nil?
      return true if options[:skip_conditions]?

      now = Time.utc
      if cutoff = not_before
        if now < (cutoff - allowed_clock_drift)
          error_msg = "Current time is earlier than NotBefore condition (#{now} < #{cutoff}#{" - #{allowed_clock_drift.seconds}s"})"
          return append_error(error_msg)
        end
      end

      if cutoff = not_on_or_after
        if now >= (cutoff + allowed_clock_drift)
          error_msg = "Current time is on or after NotOnOrAfter condition (#{now} >= #{cutoff}#{" + #{allowed_clock_drift.seconds}s"})"
          return append_error(error_msg)
        end
      end

      true
    end

    # Validates the Issuer (Of the SAML Response and the SAML Assertion)
    # @param soft [Boolean] soft Enable or Disable the soft mode (In order to raise exceptions when the response is invalid or not)
    # @return [Boolean] True if the Issuer matchs the IdP entityId, otherwise False if soft=True
    # @raise [ValidationError] if soft == false and validation fails
    #
    private def validate_issuer
      return true if settings.idp_entity_id.nil?

      begin
        obtained_issuers = issuers
      rescue  e : ValidationError
        return append_error(e.message || "Unknown error in validate_issuer")
      end

      obtained_issuers.each do |issuer|
        unless Saml::Utils.uri_match?(issuer, settings.idp_entity_id.not_nil!)
          error_msg = "Doesn't match the issuer, expected: <#{settings.idp_entity_id}>, but was: <#{issuer}>"
          return append_error(error_msg)
        end
      end

      true
    end

    # Validates that the Session haven't expired (If the response was initialized with the :allowed_clock_drift option,
    # this time validation is relaxed by the allowed_clock_drift value)
    # If fails, the error is added to the errors array
    # @param soft [Boolean] soft Enable or Disable the soft mode (In order to raise exceptions when the response is invalid or not)
    # @return [Boolean] True if the SessionNotOnOrAfter of the AuthnStatement is valid, otherwise (when expired) False if soft=True
    # @raise [ValidationError] if soft == false and validation fails
    #
    private def validate_session_expiration
      if expires_at = session_expires_at
        now = Time.utc
        unless now < (expires_at.not_nil! + allowed_clock_drift)
          error_msg = "The attributes have expired, based on the SessionNotOnOrAfter of the AuthnStatement of this Response"
          return append_error(error_msg)
        end
      end

      true
    end

    # Validates if exists valid SubjectConfirmation (If the response was initialized with the :allowed_clock_drift option,
    # timing validation are relaxed by the allowed_clock_drift value. If the response was initialized with the
    # :skip_subject_confirmation option, this validation is skipped)
    # There is also an optional Recipient check
    # If fails, the error is added to the errors array
    # @return [Boolean] True if exists a valid SubjectConfirmation, otherwise False if soft=True
    # @raise [ValidationError] if soft == false and validation fails
    #
    private def validate_subject_confirmation
      return true if options[:skip_subject_confirmation]?
      valid_subject_confirmation = false

      if subject_confirmation_nodes = xpath_from_signed_assertion("/a:Subject/a:SubjectConfirmation")
        now = Time.utc
        subject_confirmation_nodes.each do |subject_confirmation|
          if subject_confirmation["Method"]? && subject_confirmation["Method"] != "urn:oasis:names:tc:SAML:2.0:cm:bearer"
            next
          end

          confirmation_data_node = subject_confirmation.xpath_node(
            "a:SubjectConfirmationData",
            { "a" => ASSERTION }
          )

          next unless confirmation_data_node

          next if (confirmation_data_node["InResponseTo"]? && confirmation_data_node["InResponseTo"] != in_response_to) ||
                  (confirmation_data_node["Recipient"]? && !options[:skip_recipient_check]? && settings && confirmation_data_node["Recipient"] != settings.assertion_consumer_service_url)

          if not_before = parse_time(confirmation_data_node, "NotBefore")
            next if (confirmation_data_node["NotBefore"]? && now < (not_before - allowed_clock_drift))
          end

          if not_on_or_after = parse_time(confirmation_data_node, "NotOnOrAfter")
            next if (confirmation_data_node["NotOnOrAfter"]? && now >= (not_on_or_after + allowed_clock_drift))
          end

          valid_subject_confirmation = true
          break
        end
      end

      if !valid_subject_confirmation
        error_msg = "A valid SubjectConfirmation was not found on this Response"
        return append_error(error_msg)
      end

      true
    end

    # Validates the NameID element
    private def validate_name_id
      if name_id_node.nil?
        if settings.security[:want_name_id]?
          return append_error("No NameID element found in the assertion of the Response")
        end
      else
        if name_id.nil? || name_id.not_nil!.empty?
          return append_error("An empty NameID value found")
        end

        unless settings.sp_entity_id.nil? || settings.sp_entity_id.not_nil!.empty? || name_id_spnamequalifier.nil? || name_id_spnamequalifier.not_nil!.empty?
          if name_id_spnamequalifier != settings.sp_entity_id
            return append_error("The SPNameQualifier value mistmatch the SP entityID value.")
          end
        end
      end

      true
    end

    # Validates the Signature
    # @return [Boolean] True if not contains a Signature or if the Signature is valid, otherwise False if soft=True
    # @raise [ValidationError] if soft == false and validation fails
    #
    private def validate_signature
      error_msg = "Invalid Signature on SAML Response"

      # If the response contains the signature, and the assertion was encrypted, validate the original SAML Response
      # otherwise, review if the decrypted assertion contains a signature
      sig_elements = document.xpath_nodes(
        "/p:Response[@ID=$id]/ds:Signature",
        { "p" => PROTOCOL, "ds" => DSIG },
        { "id" => document.signed_element_id }
      )

      use_original = sig_elements.size == 1 || decrypted_document.nil?
      if doc = use_original ? document : decrypted_document
        # Check signature nodes
        if sig_elements.nil? || sig_elements.size == 0
          sig_elements = doc.xpath_nodes(
            "/p:Response/a:Assertion[@ID=$id]/ds:Signature",
            { "p" => PROTOCOL, "a" => ASSERTION, "ds" => DSIG },
            { "id" => doc.signed_element_id }
          )
        end

        if sig_elements.size != 1
          if sig_elements.size == 0
            append_error("Signed element id ##{doc.signed_element_id} is not found")
          else
            append_error("Signed element id ##{doc.signed_element_id} is found more than once")
          end
          return append_error(error_msg)
        end

        old_errors = @error_messages.clone

        idp_certs = settings.get_idp_cert_multi
        if idp_certs.nil? || idp_certs[:signing].empty?
          opts = {} of Symbol => String | OpenSSL::X509::Certificate
          if algo = settings.idp_cert_fingerprint_algorithm
            opts[:fingerprint_alg] = algo
          end
          fingerprint = settings.get_fingerprint
          if idp_cert = settings.get_idp_cert
            opts[:cert] = idp_cert
          end

          if fingerprint && doc.validate_document(fingerprint, @soft, opts)
            if settings.security[:check_idp_cert_expiration]?
              if Saml::Utils.is_cert_expired(idp_cert)
                error_msg = "IdP x509 certificate expired"
                return append_error(error_msg)
              end
            end
          else
            return append_error(error_msg)
          end
        else
          valid = false
          expired = false
          idp_certs[:signing].each do |idp_cert|
            valid = doc.validate_document_with_cert(idp_cert, true)
            if valid
              if settings.security[:check_idp_cert_expiration]?
                if Saml::Utils.is_cert_expired(idp_cert)
                  expired = true
                end
              end

              # At least one certificate is valid, restore the old accumulated errors
              @error_messages = old_errors
              break
            end
          end
          if expired
            error_msg = "IdP x509 certificate expired"
            return append_error(error_msg)
          end
          unless valid
            # Remove duplicated errors
            @error_messages = @error_messages.uniq
            return append_error(error_msg)
          end
        end
      else
        return append_error("Document not found")
      end

      true
    end

    private def name_id_node
      @name_id_node ||=
        begin
          encrypted_node = xpath_first_from_signed_assertion("/a:Subject/a:EncryptedID")
          if encrypted_node
            node = decrypt_nameid(encrypted_node)
          else
            node = xpath_first_from_signed_assertion("/a:Subject/a:NameID")
          end
        end
    end

    # Extracts the first appearance that matchs the subelt (pattern)
    # Search on any Assertion that is signed, or has a Response parent signed
    # @param subelt [String] The XPath pattern
    # @return [XML::Node | nil] If any matches, return the Element
    #
    private def xpath_first_from_signed_assertion(subelt = nil)
      if doc = decrypted_document.nil? ? document : decrypted_document
        node = doc.xpath_node(
          "/p:Response/a:Assertion[@ID=$id]#{subelt}",
          { "p" => PROTOCOL, "a" => ASSERTION },
          { "id" => doc.signed_element_id }
        )
        node ||= doc.xpath_node(
          "/p:Response[@ID=$id]/a:Assertion#{subelt}",
          { "p" => PROTOCOL, "a" => ASSERTION },
          { "id" => doc.signed_element_id }
        )
        node
      else
        nil
      end
    end

    # Extracts all the appearances that matchs the subelt (pattern)
    # Search on any Assertion that is signed, or has a Response parent signed
    # @param subelt [String] The XPath pattern
    # @return [Array of XML::Node] Return all matches
    #
    private def xpath_from_signed_assertion(subelt = nil)
      if doc = decrypted_document.nil? ? document : decrypted_document

        nodes = doc.xpath_nodes(
          "/p:Response/a:Assertion[@ID=$id]#{subelt}",
          { "p" => PROTOCOL, "a" => ASSERTION },
          { "id" => doc.signed_element_id }
        )

        more_nodes = doc.xpath_nodes(
          "/p:Response[@ID=$id]/a:Assertion#{subelt}",
          { "p" => PROTOCOL, "a" => ASSERTION },
          { "id" => doc.signed_element_id }
        )

        more_nodes.each do |node|
          nodes << node
        end

        nodes
      end
    end

    # Generates the decrypted_document
    # @return [XMLSecurity::SignedDocument] The SAML Response with the assertion decrypted
    #
    private def generate_decrypted_document
      if !self.settings.try(&.get_sp_key)
        raise ValidationError.new("An EncryptedAssertion found and no SP private key found on the settings to decrypt it. Be sure you provided the :settings parameter at the initialize method")
      end

      document_copy = XMLSecurity::SignedDocument.new(response)

      decrypt_assertion_from_document(document_copy)
    end

    # Obtains a SAML Response with the EncryptedAssertion element decrypted
    # @param document_copy [XMLSecurity::SignedDocument] A copy of the original SAML Response with the encrypted assertion
    # @return [XMLSecurity::SignedDocument] The SAML Response with the assertion decrypted
    #
    private def decrypt_assertion_from_document(document_copy)
      if response_node = document_copy.xpath_node(
          "/p:Response",
          { "p" => PROTOCOL }
        )
        if encrypted_assertion_node = document_copy.xpath_node("(/p:Response/EncryptedAssertion)|(/p:Response/a:EncryptedAssertion)",{ "p" => PROTOCOL, "a" => ASSERTION })
          if decrypted = decrypt_assertion(encrypted_assertion_node)
            response_node << decrypted
          else
            raise "Could not decrypt the EncryptedAssertion element"
          end
          encrypted_assertion_node.unlink
          XMLSecurity::SignedDocument.new(response_node.to_s)
        else
          raise "Could not find an EncryptedAssertion element in the response"
        end
      else
        raise "Could not find Response node"
      end
    end

    # Decrypts an EncryptedAssertion element
    # @param encrypted_assertion_node [XML::Node] The EncryptedAssertion element
    # @return [XML::Node] The decrypted EncryptedAssertion element
    #
    private def decrypt_assertion(encrypted_assertion_node : XML::Node)
      decrypt_element(encrypted_assertion_node, /(.*<\/(\w+:)?Assertion>)/m)
    end

    # Decrypts an EncryptedID element
    # @param encryptedid_node [XML::Node] The EncryptedID element
    # @return [XML::Node] The decrypted EncrypedtID element
    #
    private def decrypt_nameid(encryptedid_node : XML::Node)
      decrypt_element(encryptedid_node, /(.*<\/(\w+:)?NameID>)/m)
    end

    # Decrypts an EncryptedID element
    # @param encryptedid_node [XML::Node] The EncryptedID element
    # @return [XML::Node] The decrypted EncrypedtID element
    #
    private def decrypt_attribute(encryptedattribute_node : XML::Node)
      decrypt_element(encryptedattribute_node, /(.*<\/(\w+:)?Attribute>)/m)
    end

    # Decrypt an element
    # @param encryptedid_node [XML::Node] The encrypted element
    # @param rgrex string Regex
    # @return [XML::Node] The decrypted element
    #
    private def decrypt_element(encrypt_node : XML::Node, rgrex)
      if !settings.get_sp_key
        raise ValidationError.new("An " + (encrypt_node.try(&.name) || "unknown node name") + " found and no SP private key found on the settings to decrypt it")
      end

      if encrypt_node.name == "EncryptedAttribute"
        node_header = "<node xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">"
      else
        node_header = "<node xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">"
      end

      elem_plaintext = Saml::Utils.decrypt_data(encrypt_node, self.settings.get_sp_key_text)

      if elem_plaintext = elem_plaintext.to_s
        begin
          if match = elem_plaintext.to_s.match(rgrex)
            elem_plaintext = match[0]
          end
        rescue
          return nil
        end

        # To avoid namespace errors if saml namespace is not defined
        # create a parent node first with the namespace defined
        elem_plaintext = node_header + elem_plaintext + "</node>"
        if root = XML.parse(elem_plaintext).try(&.root)
          root.children.first
        else
          nil
        end
      else
        nil
      end
    end

    # Parse the attribute of a given node in Time format
    # @param node [XML:Node] The node
    # @param attribute [String] The attribute name
    # @return [Time|nil] The parsed value
    #
    private def parse_time(node, attribute)
      if (n = node) && (rawtime = node[attribute]?)
        Time::Format::RFC_3339.parse(rawtime)
      end
    end

    private def settings!
      self.settings.not_nil!
    end
  end
end
