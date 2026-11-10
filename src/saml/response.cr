# Only supports SAML 2.0
module Saml
  # SAML2 Authentication Response. SAML Response
  #
  # Everything read from the assertion (NameID, attributes, conditions, ...)
  # comes from the canonical bytes a signature's digest covers, re-parsed on
  # their own, never from a lookup in the received document.
  class Response < SamlMessage
    alias OptionValue = String | Bool | Float32 | Float64 | Int32 | Int64 | Time::Span | Settings | Symbol | Nil
    include ErrorHandling

    ASSERTION       = "urn:oasis:names:tc:SAML:2.0:assertion"
    PROTOCOL        = "urn:oasis:names:tc:SAML:2.0:protocol"
    DSIG            = "http://www.w3.org/2000/09/xmldsig#"
    XENC            = "http://www.w3.org/2001/04/xmlenc#"
    XSI             = "http://www.w3.org/2001/XMLSchema-instance"
    SAML_NAMESPACES = {"p" => PROTOCOL, "a" => ASSERTION, "samlp" => PROTOCOL, "saml" => ASSERTION, "ds" => DSIG}

    # Response available options
    # This is not a whitelist to allow people extending Saml:Response
    # and pass custom options
    AVAILABLE_OPTIONS = [
      :allowed_clock_drift, :check_duplicated_attributes, :matches_request_id, :settings, :skip_audience, :skip_authnstatement, :skip_conditions,
      :skip_destination, :skip_recipient_check, :skip_subject_confirmation,
    ]

    property settings : Saml::Settings
    getter document : XMLSecurity::SignedDocument
    getter decrypted_document : XMLSecurity::SignedDocument? = nil
    getter response : String
    property options : Hash(Symbol, OptionValue)
    property soft : Bool = true

    @name_id : String?
    @name_id_format : String?
    @name_id_node : XML::Node?
    @name_id_resolved = false
    @sessionindex : String?
    @expires_at : Time?
    @authn_instant : String?
    @authn_context_class_ref : String?
    @status_code : String?
    @status_message : String?
    @in_response_to : String?
    @destination : String?
    @assertion_id : String?
    @attr_statements : Saml::Attributes?
    @conditions : XML::Node?
    @not_before : Time?
    @not_on_or_after : Time?
    @audiences : Array(String)?
    @issuers : Array(String)?
    @signed_assertion : XML::Node?
    @signed_assertion_resolved = false
    # Parsed documents whose nodes are handed out; kept so they outlive them.
    @owned_documents = [] of XML::Node

    # Constructs the SAML Response.
    # @param response [String] A base64 encoded SAML response from the IdP (or the XML itself).
    # @param options  [Hash] :settings to provide the Saml::Settings object, and the
    #   validation options in AVAILABLE_OPTIONS (:allowed_clock_drift in seconds or a
    #   Time::Span, :matches_request_id, :skip_* ...).
    # @raise [ArgumentError] if response is nil
    # @raise [ValidationError] if the message is too large, or an encrypted
    #   assertion can't be decrypted
    def initialize(response : String?, options : Hash = {} of Symbol => OptionValue)
      raise ArgumentError.new("Response cannot be nil") if response.nil?

      @options = {} of Symbol => OptionValue
      options.each do |key, value|
        @options[key] = value
      end
      @settings = @options.delete(:settings).as?(Saml::Settings) || Saml::Settings.new
      @soft = @settings.soft

      @error_messages = [] of String
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
    def is_valid?(collect_errors = false) : Bool
      validate(collect_errors)
    end

    # @return [String] the NameID provided by the SAML response from the IdP.
    def name_id : String?
      @name_id ||= Utils.element_text(name_id_node)
    end

    def nameid : String?
      name_id
    end

    # @return [String] the NameID Format provided by the SAML response from the IdP.
    def name_id_format : String?
      @name_id_format ||= name_id_node.try(&.[]?("Format"))
    end

    def nameid_format : String?
      name_id_format
    end

    # @return [String] the NameID SPNameQualifier provided by the SAML response from the IdP.
    def name_id_spnamequalifier : String?
      name_id_node.try(&.[]?("SPNameQualifier"))
    end

    # @return [String] the NameID NameQualifier provided by the SAML response from the IdP.
    def name_id_namequalifier : String?
      name_id_node.try(&.[]?("NameQualifier"))
    end

    # Gets the SessionIndex from the AuthnStatement.
    def sessionindex : String?
      @sessionindex ||= xpath_first_from_signed_assertion("/a:AuthnStatement").try(&.[]?("SessionIndex"))
    end

    # Gets the Attributes from the AttributeStatement element.
    # @raise [ValidationError] if :check_duplicated_attributes is set and there are 2+ Attribute with the same Name
    def attributes : Saml::Attributes
      @attr_statements ||= begin
        attributes = Attributes.new

        xpath_from_signed_assertion("/a:AttributeStatement").each do |stmt_element|
          XMLUtil.element_children(stmt_element).each do |attr_element|
            node = attr_element.name == "EncryptedAttribute" ? decrypt_attribute(attr_element) : attr_element
            next unless node

            name = node["Name"]?
            raise ValidationError.new("Found an Attribute element with no Name") unless name

            if options[:check_duplicated_attributes]? && attributes.includes?(name)
              raise ValidationError.new("Found an Attribute element with duplicated Name")
            end

            values = [] of Attributes::AttributeValue
            XMLUtil.element_children(node).each do |value_element|
              name_ids = XMLUtil.element_children(value_element)
              if name_ids.empty?
                # SAMLCore: a nil AttributeValue has xsi:nil="true" or "1"; otherwise it is empty.
                values << (nil_value?(value_element) ? nil : Utils.element_text(value_element))
              else
                value_element.xpath_nodes("a:NameID", SAML_NAMESPACES).each do |name_id_element|
                  base_path = (qualifier = name_id_element["NameQualifier"]?) ? "#{qualifier}/" : ""
                  values << "#{base_path}#{Utils.element_text(name_id_element)}"
                end
              end
            end

            attributes.add(name, values)
          end
        end
        attributes
      end
    end

    # Gets the SessionNotOnOrAfter from the AuthnStatement.
    def session_expires_at : Time?
      @expires_at ||= parse_time(xpath_first_from_signed_assertion("/a:AuthnStatement"), "SessionNotOnOrAfter")
    end

    # Gets the AuthnInstant from the AuthnStatement.
    def authn_instant : String?
      @authn_instant ||= xpath_first_from_signed_assertion("/a:AuthnStatement").try(&.[]?("AuthnInstant"))
    end

    # Gets the AuthnContextClassRef from the AuthnStatement
    def authn_context_class_ref : String?
      @authn_context_class_ref ||= Utils.element_text(xpath_first_from_signed_assertion("/a:AuthnStatement/a:AuthnContext/a:AuthnContextClassRef"))
    end

    # Checks if the Status has the "Success" code
    def success? : Bool
      status_code == "urn:oasis:names:tc:SAML:2.0:status:Success"
    end

    # @return [String] StatusCode value from a SAML Response.
    def status_code : String?
      @status_code ||= begin
        nodes = document.xpath_nodes("/p:Response/p:Status/p:StatusCode", SAML_NAMESPACES)
        if nodes.size == 1
          code = nodes[0]["Value"]?

          unless code == "urn:oasis:names:tc:SAML:2.0:status:Success"
            statuses = document.xpath_nodes("/p:Response/p:Status/p:StatusCode/p:StatusCode", SAML_NAMESPACES).compact_map(&.[]?("Value"))
            code = ([code] + statuses).compact.join(" | ")
          end

          code
        end
      end
    end

    # @return [String] the StatusMessage value from a SAML Response.
    def status_message : String?
      @status_message ||= begin
        nodes = document.xpath_nodes("/p:Response/p:Status/p:StatusMessage", SAML_NAMESPACES)
        Utils.element_text(nodes[0]) if nodes.size == 1
      end
    end

    # Gets the Condition Element of the SAML Response if exists.
    def conditions : XML::Node?
      @conditions ||= xpath_first_from_signed_assertion("/a:Conditions")
    end

    # Gets the NotBefore Condition Element value.
    def not_before : Time?
      @not_before ||= parse_time(conditions, "NotBefore")
    end

    # Gets the NotOnOrAfter Condition Element value.
    def not_on_or_after : Time?
      @not_on_or_after ||= parse_time(conditions, "NotOnOrAfter")
    end

    # Gets the Issuers (from Response and Assertion).
    # @raise [ValidationError] when the Response or the Assertion has no Issuer or more than one
    def issuers : Array(String)
      @issuers ||= begin
        issuer_response_nodes = document.xpath_nodes("/p:Response/a:Issuer", SAML_NAMESPACES)
        unless issuer_response_nodes.size == 1
          raise ValidationError.new("Issuer of the Response not found or multiple.")
        end

        issuer_assertion_nodes = xpath_from_signed_assertion("/a:Issuer")
        unless issuer_assertion_nodes.size == 1
          raise ValidationError.new("Issuer of the Assertion not found or multiple.")
        end

        (issuer_response_nodes.to_a + issuer_assertion_nodes).compact_map { |node| Utils.element_text(node) }.uniq
      end
    end

    # @return [String|nil] The InResponseTo attribute from the SAML Response.
    def in_response_to : String?
      @in_response_to ||= document.xpath_node("/p:Response", SAML_NAMESPACES).try(&.[]?("InResponseTo"))
    end

    # @return [String|nil] Destination attribute from the SAML Response.
    def destination : String?
      @destination ||= document.xpath_node("/p:Response", SAML_NAMESPACES).try(&.[]?("Destination"))
    end

    # @return [Array] The Audience elements from the Contitions of the SAML Response.
    def audiences : Array(String)
      @audiences ||= xpath_from_signed_assertion("/a:Conditions/a:AudienceRestriction/a:Audience")
        .compact_map { |node| Utils.element_text(node) }
        .reject(&.empty?)
    end

    # The allowed clock drift on timing validation (option in seconds or a Time::Span).
    def allowed_clock_drift : Time::Span
      case drift = options[:allowed_clock_drift]?
      when Time::Span then drift.abs
      when Int32, Int64, Float32, Float64
        drift.to_f.abs.seconds
      when String then (drift.to_f? || 0.0).abs.seconds
      else             Time::Span.zero
      end
    end

    # Checks if the SAML Response contains or not an EncryptedAssertion element
    def assertion_encrypted? : Bool
      !document.xpath_node(
        "(/p:Response/EncryptedAssertion)|(/p:Response/a:EncryptedAssertion)",
        SAML_NAMESPACES
      ).nil?
    end

    def response_id : String?
      id(document)
    end

    def assertion_id : String?
      @assertion_id ||= signed_assertion.try(&.[]?("ID"))
    end

    # Validates the SAML Response (calls several validation methods)
    # @raise [ValidationError] if soft == false and validation fails
    private def validate(collect_errors = false) : Bool
      reset_errors!
      return false unless validate_response_state

      validations = [
        -> { validate_version },
        -> { validate_id },
        -> { validate_success_status },
        -> { validate_num_assertion },
        -> { validate_signed_elements },
        -> { validate_structure },
        -> { validate_no_duplicated_attributes },
        -> { validate_in_response_to },
        -> { validate_signed_assertion },
        -> { validate_one_conditions },
        -> { validate_conditions },
        -> { validate_one_authnstatement },
        -> { validate_audience },
        -> { validate_destination },
        -> { validate_issuer },
        -> { validate_session_expiration },
        -> { validate_subject_confirmation },
        -> { validate_name_id },
        -> { validate_signature },
      ]

      if collect_errors
        validations.each(&.call)
        @error_messages.empty?
      else
        validations.all?(&.call)
      end
    end

    # Validates the Status of the SAML Response
    private def validate_success_status : Bool
      return true if success?

      error_msg = "The status code of the Response was not Success"
      append_error(Saml::Utils.status_error_msg(error_msg, status_code, status_message))
    end

    # Validates the SAML Response against the specified schema.
    private def validate_structure : Bool
      structure_error_msg = "Invalid SAML Response. Not match the saml-schema-protocol-2.0.xsd"
      unless valid_saml?(document, soft)
        return append_error(structure_error_msg)
      end

      if decrypted = decrypted_document
        unless valid_saml?(decrypted, soft)
          return append_error(structure_error_msg)
        end
      end

      true
    end

    # Validates that the SAML Response provided in the initialization is not
    # empty, loads as XML, and that the settings carry an IdP certificate or fingerprint.
    private def validate_response_state : Bool
      return append_error("Blank response") if response.strip.empty?

      if load_error = document.load_error
        return append_error(load_error)
      end

      if settings.idp_cert_fingerprint.nil? && settings.idp_cert.nil? && settings.idp_cert_multi.nil?
        return append_error("No fingerprint or certificate on settings")
      end

      true
    end

    # Validates that the SAML Response contains an ID
    private def validate_id : Bool
      return append_error("Missing ID attribute on SAML Response") unless response_id
      true
    end

    # Validates the SAML version (2.0)
    private def validate_version : Bool
      return append_error("Unsupported SAML version") unless version(document) == "2.0"
      true
    end

    # Validates that the SAML Response only contains a single Assertion (encrypted or not),
    # anywhere in the document.
    private def validate_num_assertion : Bool
      error_msg = "SAML Response must contain 1 assertion"
      assertions = document.xpath_nodes("//a:Assertion", SAML_NAMESPACES)
      encrypted_assertions = document.xpath_nodes("//a:EncryptedAssertion", SAML_NAMESPACES)

      unless assertions.size + encrypted_assertions.size == 1
        return append_error(error_msg)
      end

      if decrypted = decrypted_document
        unless decrypted.xpath_nodes("//a:Assertion", SAML_NAMESPACES).size == 1
          return append_error(error_msg)
        end
      end

      true
    end

    # Validates that there are not duplicated attributes
    private def validate_no_duplicated_attributes : Bool
      if options[:check_duplicated_attributes]?
        begin
          attributes
        rescue e : ValidationError
          return append_error(e.message || "Found an Attribute element with duplicated Name")
        end
      end

      true
    end

    # Validates the Signed elements: one or two signatures, each a direct
    # child of the Response or the Assertion, each referencing its parent.
    private def validate_signed_elements : Bool
      doc = decrypted_document || document
      signature_nodes = doc.xpath_nodes("//ds:Signature", SAML_NAMESPACES)
      signed_elements = [] of String
      verified_seis = [] of String
      verified_ids = [] of String

      signature_nodes.each do |signature_node|
        parent = signature_node.parent
        signed_element = parent.try(&.name)
        if (signed_element != "Response" && signed_element != "Assertion") || !parent ||
           !{PROTOCOL, ASSERTION}.includes?(parent.namespace.try(&.href))
          return append_error("Invalid Signature Element '#{signed_element}'. SAML Response rejected")
        end

        id = parent["ID"]?
        return append_error("Signed Element must contain an ID. SAML Response rejected") unless id
        return append_error("Duplicated ID. SAML Response rejected") if verified_ids.includes?(id)
        verified_ids << id

        refs = signature_node.xpath_nodes("./ds:SignedInfo/ds:Reference", SAML_NAMESPACES)
        return append_error("Found an unexpected number of Reference elements. SAML Response rejected") if refs.size > 1
        if (ref = refs.first?) && (uri = ref["URI"]?) && !uri.empty?
          sei = uri[1..]
          return append_error("Found an invalid Signed Element. SAML Response rejected") unless sei == id
          return append_error("Duplicated Reference URI. SAML Response rejected") if verified_seis.includes?(sei)
          verified_seis << sei
        end

        signed_elements << signed_element.not_nil!
      end

      unless signature_nodes.size < 3 && !signed_elements.empty?
        return append_error("Found an unexpected number of Signature Element. SAML Response rejected")
      end

      if settings.security[:want_assertions_signed]? == true && !signed_elements.includes?("Assertion")
        return append_error("The Assertion of the Response is not signed and the SP requires it")
      end

      true
    end

    # Every assertion check below reads the signed Assertion, so say plainly
    # when there isn't one the configured IdP certificates vouch for.
    private def validate_signed_assertion : Bool
      return true if signed_assertion
      append_error("No Assertion signed by the IdP was found")
    end

    # Validates that the InResponseTo matches the :matches_request_id option, when given.
    private def validate_in_response_to : Bool
      return true unless options.has_key?(:matches_request_id)
      expected = options[:matches_request_id]?
      return true if expected.nil?
      return true if expected.to_s == in_response_to

      append_error("The InResponseTo of the Response: #{in_response_to}, does not match the ID of the AuthNRequest sent by the SP: #{expected}")
    end

    # Validates the Audience (one Audience must be the SP entity ID).
    private def validate_audience : Bool
      return true if options[:skip_audience]?
      sp_entity_id = settings.sp_entity_id
      return true if sp_entity_id.nil? || sp_entity_id.empty?

      if audiences.empty?
        return true unless settings.security[:strict_audience_validation]? == true
        return append_error("Invalid Audiences. The <AudienceRestriction> element contained only empty <Audience> elements. Expected audience #{sp_entity_id}.")
      end

      unless audiences.includes?(sp_entity_id)
        s = audiences.size > 1 ? "s" : ""
        return append_error("Invalid Audience#{s}. The audience#{s} #{audiences.join(",")}, did not match the expected audience #{sp_entity_id}")
      end

      true
    end

    # Validates the Destination (when present) against the ACS URL.
    private def validate_destination : Bool
      dest = destination
      return true if dest.nil?
      return true if options[:skip_destination]?

      return append_error("The response has an empty Destination value") if dest.empty?

      acs_url = settings.assertion_consumer_service_url
      return true if acs_url.nil? || acs_url.empty?

      unless Saml::Utils.uri_match?(dest, acs_url)
        return append_error("The response was received at #{dest} instead of #{acs_url}")
      end

      true
    end

    # Checks that the Assertion has exactly one Conditions element.
    private def validate_one_conditions : Bool
      return true if options[:skip_conditions]?

      unless xpath_from_signed_assertion("/a:Conditions").size == 1
        return append_error("The Assertion must include one Conditions element")
      end

      true
    end

    # Checks that the Assertion has exactly one AuthnStatement element.
    private def validate_one_authnstatement : Bool
      return true if options[:skip_authnstatement]?

      unless xpath_from_signed_assertion("/a:AuthnStatement").size == 1
        return append_error("The Assertion must include one AuthnStatement element")
      end

      true
    end

    # Validates the Conditions' NotBefore and NotOnOrAfter, relaxed by the allowed clock drift.
    private def validate_conditions : Bool
      return true if conditions.nil?
      return true if options[:skip_conditions]?

      now = Time.utc
      drift = allowed_clock_drift
      begin
        if (cutoff = not_before) && now < (cutoff - drift)
          return append_error("Current time is earlier than NotBefore condition (#{now} < #{cutoff}#{drift_note(drift, "-")})")
        end

        if (cutoff = not_on_or_after) && now >= (cutoff + drift)
          return append_error("Current time is on or after NotOnOrAfter condition (#{now} >= #{cutoff}#{drift_note(drift, "+")})")
        end
      rescue e : ValidationError
        return append_error(e.message || "Invalid Conditions time")
      end

      true
    end

    # Validates the Issuer (Of the SAML Response and the SAML Assertion)
    private def validate_issuer : Bool
      idp_entity_id = settings.idp_entity_id
      return true if idp_entity_id.nil?

      begin
        obtained_issuers = issuers
      rescue e : ValidationError
        return append_error(e.message || "Issuer not found")
      end

      obtained_issuers.each do |issuer|
        unless Saml::Utils.uri_match?(issuer, idp_entity_id)
          return append_error("Doesn't match the issuer, expected: <#{idp_entity_id}>, but was: <#{issuer}>")
        end
      end

      true
    end

    # Validates that the Session haven't expired
    private def validate_session_expiration : Bool
      begin
        expires_at = session_expires_at
      rescue e : ValidationError
        return append_error(e.message || "Invalid SessionNotOnOrAfter")
      end
      return true unless expires_at

      unless Time.utc < (expires_at + allowed_clock_drift)
        return append_error("The attributes have expired, based on the SessionNotOnOrAfter of the AuthnStatement of this Response")
      end

      true
    end

    # Validates that a bearer SubjectConfirmation with valid data exists.
    private def validate_subject_confirmation : Bool
      return true if options[:skip_subject_confirmation]?
      valid_subject_confirmation = false
      now = Time.utc
      drift = allowed_clock_drift

      xpath_from_signed_assertion("/a:Subject/a:SubjectConfirmation").each do |subject_confirmation|
        if (method = subject_confirmation["Method"]?) && method != "urn:oasis:names:tc:SAML:2.0:cm:bearer"
          next
        end

        confirmation_data_node = subject_confirmation.xpath_node("a:SubjectConfirmationData", SAML_NAMESPACES)
        next unless confirmation_data_node

        begin
          irt = confirmation_data_node["InResponseTo"]?
          next if irt && irt != in_response_to

          if (nb = parse_time(confirmation_data_node, "NotBefore")) && now < (nb - drift)
            next
          end

          if (noa = parse_time(confirmation_data_node, "NotOnOrAfter")) && now >= (noa + drift)
            next
          end
        rescue ValidationError
          next
        end

        recipient = confirmation_data_node["Recipient"]?
        next if recipient && !options[:skip_recipient_check]? && recipient != settings.assertion_consumer_service_url

        valid_subject_confirmation = true
        break
      end

      unless valid_subject_confirmation
        return append_error("A valid SubjectConfirmation was not found on this Response")
      end

      true
    end

    # Validates the NameID element
    private def validate_name_id : Bool
      if name_id_node.nil?
        if settings.security[:want_name_id]? == true
          return append_error("No NameID element found in the assertion of the Response")
        end
      else
        value = name_id
        return append_error("An empty NameID value found") if value.nil? || value.empty?

        sp_entity_id = settings.sp_entity_id
        qualifier = name_id_spnamequalifier
        unless sp_entity_id.nil? || sp_entity_id.empty? || qualifier.nil? || qualifier.empty?
          if qualifier != sp_entity_id
            return append_error("SPNameQualifier value does not match the SP entityID value.")
          end
        end
      end

      true
    end

    # Verifies every signature the Response carries: the Response's own and
    # the Assertion's (decrypted when it was encrypted). Only the configured
    # IdP certificates are trusted; in fingerprint mode the signature's own
    # KeyInfo certificate is used once its fingerprint matches.
    private def validate_signature : Bool
      error_msg = "Invalid Signature on SAML Response"

      targets = signature_targets
      if targets.empty?
        if id = document.signed_element_id
          append_error("Signed element id ##{id} is not found")
        else
          append_error("No signature found on the Response or its Assertion")
        end
        return append_error(error_msg)
      end

      certificates = settings.idp_signing_certificates
      fingerprint = certificates.empty? ? settings.get_fingerprint : nil
      if certificates.empty? && fingerprint.nil?
        return append_error("No fingerprint or certificate on settings")
      end

      targets.each do |doc, sig|
        ref = doc.reference_for(sig)
        if ref.is_a?(String)
          append_error(ref, true)
          return append_error(error_msg)
        end

        cert = if fingerprint
                 verify_with_fingerprint(doc, ref, fingerprint)
               else
                 verify_with_certificates(doc, ref, certificates)
               end
        return append_error(error_msg) unless cert

        if settings.security[:check_idp_cert_expiration]? == true && Saml::Utils.is_cert_expired(cert)
          return append_error("IdP x509 certificate expired")
        end
      end

      true
    end

    private def verify_with_certificates(doc, ref, certificates) : OpenSSL::X509::Certificate?
      if text = ref.key_info_certificate_text
        key_info_cert = doc.load_cert(text)
        unless key_info_cert
          append_error("Document Certificate Error", true)
          return nil
        end
        unless certificates.any? { |cert| cert.to_der == key_info_cert.to_der }
          append_error("Certificate of the Signature element does not match provided certificate", true)
          return nil
        end
      end

      verified_certificate(doc, ref, certificates)
    end

    private def verify_with_fingerprint(doc, ref, fingerprint) : OpenSSL::X509::Certificate?
      text = ref.key_info_certificate_text
      unless text
        append_error("Certificate element missing in response (ds:X509Certificate) and not cert provided at settings", true)
        return nil
      end

      cert = doc.load_cert(text)
      unless cert
        append_error("Document Certificate Error", true)
        return nil
      end

      digest = XMLSecurity::BaseDocument.algorithm(settings.idp_cert_fingerprint_algorithm)
      digest << cert.to_der
      expected = fingerprint.gsub(/[^a-zA-Z0-9]/, "").downcase
      unless Crypto::Subtle.constant_time_compare(digest.hexfinal.to_slice, expected.to_slice)
        append_error("Fingerprint mismatch", true)
        return nil
      end

      verified_certificate(doc, ref, [cert])
    end

    private def verified_certificate(doc, ref, certificates) : OpenSSL::X509::Certificate?
      unless ref.digest_matches?
        append_error("Digest mismatch", true)
        return nil
      end

      cert = certificates.find { |candidate| ref.signature_valid?(candidate) }
      append_error("Key validation error", true) unless cert
      cert
    end

    # The signatures to verify, with the document each lives in.
    private def signature_targets : Array({XMLSecurity::SignedDocument, XML::Node})
      targets = [] of {XMLSecurity::SignedDocument, XML::Node}
      if sig = response_signature
        targets << {document, sig}
      end
      assertion_doc = decrypted_document || document
      if sig = assertion_signature(assertion_doc)
        targets << {assertion_doc, sig}
      end
      targets
    end

    private def response_signature : XML::Node?
      XMLUtil.only_node(document, "/p:Response/ds:Signature", SAML_NAMESPACES)
    end

    private def assertion_signature(doc : XMLSecurity::SignedDocument) : XML::Node?
      XMLUtil.only_node(doc, "/p:Response/a:Assertion/ds:Signature", SAML_NAMESPACES)
    end

    private def name_id_node : XML::Node?
      return @name_id_node if @name_id_resolved
      # Resolved only on success, so a missing key raises on every call.
      node = if encrypted_node = xpath_first_from_signed_assertion("/a:Subject/a:EncryptedID")
               decrypt_nameid(encrypted_node)
             else
               xpath_first_from_signed_assertion("/a:Subject/a:NameID")
             end
      @name_id_resolved = true
      @name_id_node = node
    end

    # The Assertion as its signature covers it: from the Assertion's own
    # signature when it has one, else from the Response's signature (an
    # EncryptedAssertion is decrypted from those verified bytes).
    private def signed_assertion : XML::Node?
      return @signed_assertion if @signed_assertion_resolved
      @signed_assertion_resolved = true
      @signed_assertion = find_signed_assertion
    end

    private def find_signed_assertion : XML::Node?
      assertion_doc = decrypted_document || document

      if sig = assertion_signature(assertion_doc)
        root = verified_root(assertion_doc, sig)
        return root if root && root.name == "Assertion" && root.namespace.try(&.href) == ASSERTION
        return nil
      end

      if (sig = response_signature) && (root = verified_root(document, sig))
        return nil unless root.name == "Response" && root.namespace.try(&.href) == PROTOCOL

        assertions = root.xpath_nodes("./a:Assertion", SAML_NAMESPACES)
        encrypted = root.xpath_nodes("./a:EncryptedAssertion | ./EncryptedAssertion", SAML_NAMESPACES)
        if assertions.size == 1 && encrypted.empty?
          return assertions[0]
        elsif assertions.empty? && encrypted.size == 1
          return decrypt_assertion(encrypted[0])
        end
      end

      nil
    end

    # Re-parses the canonical bytes a signature covers.
    private def verified_root(doc : XMLSecurity::SignedDocument, sig : XML::Node) : XML::Node?
      ref = doc.reference_for(sig)
      return nil unless ref.is_a?(XMLSecurity::SignedReference)
      return nil unless trusted?(doc, ref)

      parsed = XMLUtil.safe_parse(ref.canonical_xml)
      @owned_documents << parsed
      root = parsed.root
      root && root["ID"]? == ref.element_id ? root : nil
    rescue XMLLoadError
      nil
    end

    # Whether the reference's digest and signature check out against the
    # configured IdP certificates (or the fingerprinted KeyInfo one), so the
    # getters never return data from a forged signature.
    private def trusted?(doc : XMLSecurity::SignedDocument, ref : XMLSecurity::SignedReference) : Bool
      certificates = settings.idp_signing_certificates
      fingerprint = settings.get_fingerprint
      # Nothing to verify with: is_valid? fails anyway, reads stay as in ruby-saml.
      return true if certificates.empty? && fingerprint.nil?
      return false unless ref.digest_matches?

      if certificates.empty?
        text = ref.key_info_certificate_text
        return false unless fingerprint && text && (cert = doc.load_cert(text))

        digest = XMLSecurity::BaseDocument.algorithm(settings.idp_cert_fingerprint_algorithm)
        digest << cert.to_der
        expected = fingerprint.gsub(/[^a-zA-Z0-9]/, "").downcase
        return false unless Crypto::Subtle.constant_time_compare(digest.hexfinal.to_slice, expected.to_slice)
        certificates = [cert]
      end

      certificates.any? { |cert| ref.signature_valid?(cert) }
    end

    # First match of *subelt* under the signed Assertion.
    private def xpath_first_from_signed_assertion(subelt = nil) : XML::Node?
      xpath_from_signed_assertion(subelt).first?
    end

    # All matches of *subelt* (e.g. "/a:Conditions") under the signed Assertion.
    private def xpath_from_signed_assertion(subelt = nil) : Array(XML::Node)
      assertion = signed_assertion
      return [] of XML::Node unless assertion
      return [assertion] if subelt.nil? || subelt.empty?

      assertion.xpath_nodes(".#{subelt}", SAML_NAMESPACES).to_a
    end

    # Generates the decrypted_document
    private def generate_decrypted_document : XMLSecurity::SignedDocument
      if settings.get_sp_decryption_keys.empty?
        raise ValidationError.new("An EncryptedAssertion found and no SP private key found on the settings to decrypt it. Be sure you provided the :settings parameter at the initialize method")
      end

      decrypt_assertion_from_document(XMLSecurity::SignedDocument.new(response))
    end

    # A copy of the Response with its EncryptedAssertion replaced by the decrypted Assertion.
    private def decrypt_assertion_from_document(document_copy : XMLSecurity::SignedDocument) : XMLSecurity::SignedDocument
      raise ValidationError.new(document_copy.load_error.not_nil!) unless document_copy.loaded?

      encrypted_assertion_node = document_copy.xpath_node(
        "(/p:Response/EncryptedAssertion)|(/p:Response/a:EncryptedAssertion)",
        SAML_NAMESPACES
      )
      raise ValidationError.new("Could not find an EncryptedAssertion element in the response") unless encrypted_assertion_node

      decrypted = decrypt_assertion(encrypted_assertion_node)
      raise ValidationError.new("Could not decrypt the EncryptedAssertion element") unless decrypted

      target = document_copy.xml_document.to_unsafe.as(LibXML::Doc*)
      copy = LibSamlXML.xmlDocCopyNode(decrypted.to_unsafe, target, 1)
      raise ValidationError.new("Could not decrypt the EncryptedAssertion element") if copy.null?
      LibSamlXML.xmlAddPrevSibling(encrypted_assertion_node.to_unsafe, copy)
      encrypted_assertion_node.unlink

      XMLSecurity::SignedDocument.new(document_copy.to_s)
    end

    # Decrypts an EncryptedAssertion element
    private def decrypt_assertion(encrypted_assertion_node : XML::Node) : XML::Node?
      decrypt_element(encrypted_assertion_node, /(.*<\/(\w+:)?Assertion>)/m)
    end

    # Decrypts an EncryptedID element
    private def decrypt_nameid(encrypted_id_node : XML::Node) : XML::Node?
      decrypt_element(encrypted_id_node, /(.*<\/(\w+:)?NameID>)/m)
    end

    # Decrypts an EncryptedAttribute element
    private def decrypt_attribute(encrypted_attribute_node : XML::Node) : XML::Node?
      decrypt_element(encrypted_attribute_node, /(.*<\/(\w+:)?Attribute>)/m)
    end

    # Decrypts an element with the SP keys. The plaintext must be exactly one
    # well-formed element.
    private def decrypt_element(encrypt_node : XML::Node, regexp : Regex) : XML::Node?
      keys = settings.get_sp_decryption_keys
      if keys.empty?
        raise ValidationError.new("An #{encrypt_node.name} found and no SP private key found on the settings to decrypt it")
      end

      node_header = if encrypt_node.name == "EncryptedAttribute"
                      %(<node xmlns:saml="#{ASSERTION}" xmlns:xsi="#{XSI}">)
                    else
                      %(<node xmlns:saml="#{ASSERTION}">)
                    end

      plaintext = Saml::Utils.decrypt_multi(encrypt_node, keys)
      return nil unless plaintext && (match = plaintext.match(regexp))

      parsed = begin
        XMLUtil.safe_parse(node_header + match[0] + "</node>")
      rescue XMLLoadError
        return nil
      end
      @owned_documents << parsed

      wrapper = parsed.root
      return nil unless wrapper
      children = XMLUtil.element_children(wrapper)
      children.size == 1 ? children[0] : nil
    end

    private def nil_value?(element : XML::Node) : Bool
      element.attributes.each do |attribute|
        next unless attribute.name == "nil"
        next unless attribute.namespace.try(&.href) == XSI
        return {"true", "1"}.includes?(attribute.content)
      end
      false
    end

    private def drift_note(drift : Time::Span, sign : String) : String
      " #{sign} #{(drift.total_seconds + Float64::EPSILON).ceil.to_i}s"
    end

    # Parses a time attribute. A value that isn't a valid xs:dateTime raises,
    # so a broken condition never counts as no condition.
    private def parse_time(node : XML::Node?, attribute : String) : Time?
      return nil unless node
      raw = node[attribute]?
      return nil unless raw

      Time::Format::RFC_3339.parse(raw)
    rescue Time::Format::Error
      raise ValidationError.new("Invalid #{attribute} value: #{raw}")
    end
  end
end
