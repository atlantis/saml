# Only supports SAML 2.0
module Saml
  # SAML2 Logout Request (SLO IdP initiated, Parser)
  #
  # The signature is only checked when :get_params carry a Signature (the
  # HTTP-Redirect binding), as in ruby-saml; an unsigned request is accepted.
  class SloLogoutrequest < SamlMessage
    include ErrorHandling
    include RedirectSignature

    property settings : Settings?
    getter document : XMLSecurity::SignedDocument
    getter request : String
    getter options : Hash(Symbol, RedirectSignature::OptionValue)
    property soft : Bool = true

    @name_id : String?
    @name_id_format : String?
    @name_id_node : XML::Node?
    @name_id_resolved = false
    @issuer : String?
    @not_on_or_after : Time?
    @owned_documents = [] of XML::Node

    # @param request [String] A base64 encoded (and maybe deflated) Logout Request from the IdP.
    # @param options [Hash] :settings, :allowed_clock_drift, :get_params / :raw_get_params
    #   (to check a redirect binding signature), :relax_signature_validation
    # @raise [ArgumentError] If Request is nil
    def initialize(request : String?, options : Hash = {} of Symbol => RedirectSignature::OptionValue)
      raise ArgumentError.new("Request cannot be nil") if request.nil?

      @error_messages = [] of String
      @options = {} of Symbol => RedirectSignature::OptionValue
      options.each { |key, value| @options[key] = value }
      @settings = @options[:settings]?.as?(Settings)
      @soft = @settings.try(&.soft) != false

      @request = decode_raw_saml(request, settings)
      @document = XMLSecurity::SignedDocument.new(@request, @error_messages)
    end

    def request_id : String?
      id(document)
    end

    def is_valid?(collect_errors = false) : Bool
      validate(collect_errors)
    end

    # @return [String] Gets the NameID of the Logout Request.
    def name_id : String?
      @name_id ||= Utils.element_text(name_id_node)
    end

    def nameid : String?
      name_id
    end

    # @return [String] Gets the NameID Format of the Logout Request.
    def name_id_format : String?
      @name_id_format ||= name_id_node.try(&.[]?("Format"))
    end

    def nameid_format : String?
      name_id_format
    end

    def name_id_node : XML::Node?
      return @name_id_node if @name_id_resolved
      @name_id_resolved = true
      ns = {"p" => PROTOCOL, "a" => ASSERTION}
      @name_id_node = if encrypted_node = document.xpath_node("/p:LogoutRequest/a:EncryptedID", ns)
                        decrypt_nameid(encrypted_node)
                      else
                        document.xpath_node("/p:LogoutRequest/a:NameID", ns)
                      end
    end

    # Decrypts an EncryptedID element with the SP keys.
    def decrypt_nameid(encrypted_id_node : XML::Node) : XML::Node?
      keys = settings.try(&.get_sp_decryption_keys) || [] of OpenSSL::PKey::RSA
      if keys.empty?
        raise ValidationError.new("An #{encrypted_id_node.name} found and no SP private key found on the settings to decrypt it")
      end

      plaintext = Utils.decrypt_multi(encrypted_id_node, keys)
      return nil unless plaintext && (match = plaintext.match(/(.*<\/(\w+:)?NameID>)/m))

      parsed = XMLUtil.safe_parse(%(<node xmlns:saml="#{ASSERTION}">) + match[0] + "</node>")
      @owned_documents << parsed
      children = parsed.root.try { |root| XMLUtil.element_children(root) } || [] of XML::Node
      children.size == 1 ? children[0] : nil
    rescue XMLLoadError
      nil
    end

    # @return [String|nil] Gets the ID attribute from the Logout Request. if exists.
    def id : String?
      super(document)
    end

    # @return [String] Gets the Issuer from the Logout Request.
    def issuer : String?
      @issuer ||= Utils.element_text(document.xpath_node("/p:LogoutRequest/a:Issuer", {"p" => PROTOCOL, "a" => ASSERTION}))
    end

    # @return [Time|nil] Gets the NotOnOrAfter Attribute value if exists.
    def not_on_or_after : Time?
      @not_on_or_after ||= begin
        node = document.xpath_node("/p:LogoutRequest", {"p" => PROTOCOL})
        if raw = node.try(&.[]?("NotOnOrAfter"))
          Time::Format::RFC_3339.parse(raw)
        end
      end
    end

    # @return [Array] Gets the SessionIndex if exists (Supported multiple values). Empty Array if none found
    def session_indexes : Array(String)
      document.xpath_nodes("/p:LogoutRequest/p:SessionIndex", {"p" => PROTOCOL}).compact_map { |node| Utils.element_text(node) }
    end

    private def allowed_clock_drift : Time::Span
      case drift = options[:allowed_clock_drift]?
      when Time::Span then drift.abs
      when Int32, Int64, Float32, Float64
        drift.to_f.abs.seconds
      when String then (drift.to_f? || 0.0).abs.seconds
      else             Time::Span.zero
      end
    end

    private def validate(collect_errors = false) : Bool
      reset_errors!

      validations = [
        -> { validate_request_state },
        -> { validate_id },
        -> { validate_version },
        -> { validate_structure },
        -> { validate_not_on_or_after },
        -> { validate_issuer },
        -> { validate_signature },
      ]

      if collect_errors
        validations.each(&.call)
        @error_messages.empty?
      else
        validations.all?(&.call)
      end
    end

    private def validate_id : Bool
      return append_error("Missing ID attribute on Logout Request") unless id
      true
    end

    private def validate_version : Bool
      return append_error("Unsupported SAML version") unless version(document) == "2.0"
      true
    end

    private def validate_not_on_or_after : Bool
      now = Time.utc
      drift = allowed_clock_drift
      begin
        # A nanosecond of slack, like ruby-saml's Float::EPSILON.
        if (limit = not_on_or_after) && now >= (limit + drift + 1.nanosecond)
          return append_error("Current time is on or after NotOnOrAfter (#{now} >= #{limit} + #{(drift.total_seconds + Float64::EPSILON).ceil.to_i}s)")
        end
      rescue Time::Format::Error
        return append_error("Invalid NotOnOrAfter value")
      end

      true
    end

    private def validate_structure : Bool
      unless valid_saml?(document, soft)
        return append_error("Invalid SAML Logout Request. Not match the saml-schema-protocol-2.0.xsd")
      end

      true
    end

    private def validate_request_state : Bool
      return append_error("Blank logout request") if request.strip.empty?
      if load_error = document.load_error
        return append_error(load_error)
      end
      true
    end

    private def validate_issuer : Bool
      idp_entity_id = settings.try(&.idp_entity_id)
      return true if idp_entity_id.nil?
      value = issuer
      return true if value.nil?

      unless Utils.uri_match?(value, idp_entity_id)
        return append_error("Doesn't match the issuer, expected: <#{idp_entity_id}>, but was: <#{value}>")
      end

      true
    end

    private def validate_signature : Bool
      current = settings
      return true unless current

      case result = check_redirect_signature("SAMLRequest", current, options)
      when nil, true then true
      when String    then append_error(result)
      else                append_error("Invalid Signature on Logout Request")
      end
    end
  end
end
