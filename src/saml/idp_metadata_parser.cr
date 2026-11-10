require "http/client"

# Only supports SAML 2.0
module Saml
  # Auxiliary class to retrieve and parse the Identity Provider Metadata
  #
  # parse_remote fetches whatever URL it is given (an SSRF risk when the URL
  # comes from a user): validate it before calling. Metadata is parsed with
  # the same strict parser as messages (no DTDs, no entities, no network).
  class IdpMetadataParser
    module SamlMetadata
      module Vocabulary
        METADATA       = "urn:oasis:names:tc:SAML:2.0:metadata"
        DSIG           = "http://www.w3.org/2000/09/xmldsig#"
        NAME_FORMAT    = "urn:oasis:names:tc:SAML:2.0:attrname-format:*"
        SAML_ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion"
      end

      NAMESPACE = {
        "md"         => Vocabulary::METADATA,
        "NameFormat" => Vocabulary::NAME_FORMAT,
        "saml"       => Vocabulary::SAML_ASSERTION,
        "ds"         => Vocabulary::DSIG,
      }
    end

    include SamlMetadata::Vocabulary

    alias Option = String | Array(String) | Int32 | Bool | Settings | Hash(Symbol, Settings::Value) | Nil
    alias Parsed = Hash(Symbol, Settings::Value)

    # Remote metadata larger than this is refused; aggregates may need more (:max_bytesize).
    DEFAULT_MAX_BYTESIZE = 10_000_000
    DEFAULT_TIMEOUT      = 10.seconds

    getter document : XML::Node?
    getter response : HTTP::Client::Response?
    getter options = {} of Symbol => Option

    # fetch IdP descriptors from a metadata document
    def self.get_idps(metadata_document : XML::Node, only_entity_id : String? = nil) : Array(XML::Node)
      if only_entity_id
        metadata_document.xpath_nodes("//md:EntityDescriptor[@entityID=$id]/md:IDPSSODescriptor",
          SamlMetadata::NAMESPACE, {"id" => only_entity_id}).to_a
      else
        metadata_document.xpath_nodes("//md:EntityDescriptor/md:IDPSSODescriptor", SamlMetadata::NAMESPACE).to_a
      end
    end

    # Fetches the IdP metadata and returns Settings with the IdP values.
    # @param url [String] http(s) URL of the metadata
    # @param validate_cert [Boolean] check the server's TLS certificate
    # @param options [Hash] as for #parse, plus :max_bytesize
    # @raise [HttpError] Failure to fetch remote IdP metadata
    def parse_remote(url : String, validate_cert = true, options : Hash = {} of Symbol => Option) : Settings
      parse(get_idp_metadata(url, validate_cert, options), options)
    end

    # Like parse_remote, returning the first IdP's values as a Hash.
    def parse_remote_to_hash(url : String, validate_cert = true, options : Hash = {} of Symbol => Option) : Parsed
      parse_remote_to_array(url, validate_cert, options)[0]
    end

    # Like parse_remote, returning every IdP's values.
    def parse_remote_to_array(url : String, validate_cert = true, options : Hash = {} of Symbol => Option) : Array(Parsed)
      parse_to_array(get_idp_metadata(url, validate_cert, options), options)
    end

    # Parses the IdP metadata and returns Settings with the IdP values.
    #
    # @option options [Saml::Settings, Hash] :settings the Settings to merge the metadata into, or overrides for new Settings
    # @option options [String] :entity_id use the IdP with this entityID (else the first)
    # @option options [String, Array<String>] :sso_binding preferred bindings for the single sign-on URL
    # @option options [String, Array<String>] :slo_binding preferred bindings for the single logout URL
    # @option options [String, Array<String>] :name_id_format preferred NameIDFormat values
    # @raise [ArgumentError] when the metadata has no IDPSSODescriptor
    # @raise [XMLLoadError] when the metadata isn't well-formed or uses DTDs
    def parse(idp_metadata : String, options : Hash = {} of Symbol => Option) : Settings
      parsed_metadata = parse_to_hash(idp_metadata, options)

      if (duration = parsed_metadata[:cache_duration]?.as?(String))
        cache_valid_until = Utils.parse_duration(duration).to_i64
        valid_until = parsed_metadata[:valid_until]?.as?(String)
        if valid_until.nil? || cache_valid_until < Time::Format::ISO_8601_DATE_TIME.parse(valid_until).to_unix
          parsed_metadata[:valid_until] = Time.unix(cache_valid_until).to_s("%Y-%m-%dT%H:%M:%SZ")
        end
      end
      # Settings only carry valid_until
      parsed_metadata.delete(:cache_duration)

      case settings = options[:settings]?
      when Settings
        merge_parsed_metadata_into(settings, parsed_metadata)
      when Hash
        overrides = {} of Symbol => Settings::Value
        settings.each { |key, value| overrides[key.as(Symbol)] = value.as(Settings::Value) }
        Settings.new(overrides.merge(parsed_metadata))
      else
        Settings.new(parsed_metadata)
      end
    end

    # Parses the metadata and returns the first IdP's values as a Hash.
    def parse_to_hash(idp_metadata : String, options : Hash = {} of Symbol => Option) : Parsed
      parse_to_array(idp_metadata, options)[0]
    end

    # Parses the metadata and returns every IdP's values (or only :entity_id's).
    def parse_to_array(idp_metadata : String, options : Hash = {} of Symbol => Option) : Array(Parsed)
      parse_to_idp_metadata_array(idp_metadata, options).map(&.to_hash(@options))
    end

    def parse_to_idp_metadata_array(idp_metadata : String, options : Hash = {} of Symbol => Option) : Array(IdpMetadata)
      document = XMLUtil.safe_parse(idp_metadata)
      @document = document
      @options = {} of Symbol => Option
      options.each { |key, value| @options[key.as(Symbol)] = value.as(Option) }

      entity_id = @options[:entity_id]?.as?(String)
      idpsso_descriptors = self.class.get_idps(document, entity_id)
      if idpsso_descriptors.empty?
        raise ArgumentError.new("idp_metadata must contain an IDPSSODescriptor element")
      end

      idpsso_descriptors.map { |descriptor| IdpMetadata.new(descriptor, descriptor.parent.try(&.[]?("entityID")), document) }
    end

    # Fetches the metadata over http(s): no redirects, a timeout, a size cap,
    # and the TLS certificate checked unless *validate_cert* is false.
    private def get_idp_metadata(url : String, validate_cert : Bool, options) : String
      uri = URI.parse(url)
      scheme = uri.scheme
      raise ArgumentError.new("url must begin with http or https") unless scheme == "http" || scheme == "https"
      host = uri.host
      raise ArgumentError.new("url must have a host") if host.nil? || host.empty?

      max = options[:max_bytesize]?.as?(Int32) || DEFAULT_MAX_BYTESIZE

      tls = nil
      if scheme == "https"
        context = OpenSSL::SSL::Context::Client.new
        # Self-signed IdP servers are common, so callers may opt out.
        context.verify_mode = OpenSSL::SSL::VerifyMode::NONE unless validate_cert
        tls = context
      end

      client = HTTP::Client.new(host, uri.port, tls: tls)
      client.connect_timeout = DEFAULT_TIMEOUT
      client.read_timeout = DEFAULT_TIMEOUT
      if user = uri.user
        client.basic_auth(URI.decode_www_form(user), URI.decode_www_form(uri.password || ""))
      end

      begin
        client.get(uri.request_target) do |response|
          @response = response
          unless response.success?
            raise HttpError.new("Failed to fetch idp metadata: #{response.status_code}: #{response.status_message}")
          end

          body = IO::Memory.new
          copied = IO.copy(response.body_io, body, max + 1)
          raise HttpError.new("Failed to fetch idp metadata: larger than #{max} bytes") if copied > max
          body.to_s
        end
      ensure
        client.close
      end
    rescue error : IO::Error | Socket::Error | OpenSSL::Error
      raise HttpError.new("Failed to fetch idp metadata: #{error.message}")
    end

    class IdpMetadata
      getter idpsso_descriptor : XML::Node
      getter entity_id : String?
      @certificates : Hash(String, Array(String))?
      @certificates_resolved = false
      # Keeps the parsed document alive while its nodes are in use.
      @document : XML::Node

      def initialize(@idpsso_descriptor, @entity_id, @document)
      end

      def to_hash(options = {} of Symbol => Option) : Parsed
        sso_binding = options[:sso_binding]?
        slo_binding = options[:slo_binding]?
        hash = {
          :idp_entity_id                => @entity_id,
          :name_identifier_format       => idp_name_id_format(options[:name_id_format]?),
          :idp_sso_service_url          => single_signon_service_url(sso_binding),
          :idp_sso_service_binding      => single_signon_service_binding(sso_binding),
          :idp_slo_service_url          => single_logout_service_url(slo_binding),
          :idp_slo_service_binding      => single_logout_service_binding(slo_binding),
          :idp_slo_response_service_url => single_logout_response_service_url(slo_binding),
          :idp_attribute_names          => attribute_names,
          :idp_cert                     => nil,
          :idp_cert_fingerprint         => nil,
          :idp_cert_multi               => nil,
          :valid_until                  => valid_until,
          :cache_duration               => cache_duration,
        } of Symbol => Settings::Value
        merge_certificates_into(hash) unless certificates.nil?
        hash
      end

      # @return [String|nil] 'validUntil' attribute of metadata
      def valid_until : String?
        @document.root.try(&.[]?("validUntil"))
      end

      # @return [String|nil] 'cacheDuration' attribute of metadata
      def cache_duration : String?
        @document.root.try(&.[]?("cacheDuration"))
      end

      # @return [String|nil] the first NameIDFormat in *name_id_priority* the IdP offers (or its first)
      def idp_name_id_format(name_id_priority = nil) : String?
        first_ranked(@idpsso_descriptor.xpath_nodes("md:NameIDFormat", SamlMetadata::NAMESPACE)
          .compact_map { |node| Utils.element_text(node) }, name_id_priority)
      end

      # @return [String|nil] SingleSignOnService binding if exists
      def single_signon_service_binding(binding_priority = nil) : String?
        first_ranked(attribute_values("md:SingleSignOnService", "Binding"), binding_priority)
      end

      # @return [String|nil] SingleLogoutService binding if exists
      def single_logout_service_binding(binding_priority = nil) : String?
        first_ranked(attribute_values("md:SingleLogoutService", "Binding"), binding_priority)
      end

      # @return [String|nil] SingleSignOnService endpoint if exists
      def single_signon_service_url(binding_priority = nil) : String?
        binding = single_signon_service_binding(binding_priority)
        endpoint("md:SingleSignOnService", binding, "Location") if binding
      end

      # @return [String|nil] SingleLogoutService endpoint if exists
      def single_logout_service_url(binding_priority = nil) : String?
        binding = single_logout_service_binding(binding_priority)
        endpoint("md:SingleLogoutService", binding, "Location") if binding
      end

      # @return [String|nil] SingleLogoutService response url if exists
      def single_logout_response_service_url(binding_priority = nil) : String?
        binding = single_logout_service_binding(binding_priority)
        endpoint("md:SingleLogoutService", binding, "ResponseLocation") if binding
      end

      # @return [Hash|nil] "signing"/"encryption" to base64 certificates
      def certificates : Hash(String, Array(String))?
        return @certificates if @certificates_resolved
        @certificates_resolved = true

        signing = cert_texts("md:KeyDescriptor[not(contains(@use, 'encryption'))]/ds:KeyInfo/ds:X509Data/ds:X509Certificate")
        encryption = cert_texts("md:KeyDescriptor[not(contains(@use, 'signing'))]/ds:KeyInfo/ds:X509Data/ds:X509Certificate")
        return nil if signing.empty? && encryption.empty?

        certs = {} of String => Array(String)
        certs["signing"] = signing unless signing.empty?
        certs["encryption"] = encryption unless encryption.empty?
        @certificates = certs
      end

      # @return [String|nil] the colon-separated fingerprint of the certificate
      def fingerprint(certificate : String?, fingerprint_algorithm = XMLSecurity::Document::SHA1) : String?
        return nil unless certificate

        decoded = Base64.decode(certificate.gsub(/\s/, ""))
        # Some IdPs publish base64 of a PEM file rather than of the DER.
        cert = if String.new(decoded).includes?("-----BEGIN CERTIFICATE-----")
                 OpenSSL::X509::Certificate.new(String.new(decoded))
               else
                 OpenSSL::X509::Certificate.from_der(decoded)
               end
        digest = XMLSecurity::BaseDocument.algorithm(fingerprint_algorithm.try(&.to_s))
        digest << cert.to_der
        digest.hexfinal.upcase.scan(/../).map(&.[0]).join(":")
      rescue Base64::Error | OpenSSL::Error
        nil
      end

      # @return [Array] the names of all SAML attributes if any exist
      def attribute_names : Array(String)
        attribute_values("saml:Attribute", "Name")
      end

      def merge_certificates_into(parsed_metadata : Parsed)
        certs = certificates
        return unless certs

        if (certs.size == 1 && (certificates_has_one("signing") || certificates_has_one("encryption"))) ||
           (certificates_has_one("signing") && certificates_has_one("encryption") && certs["signing"][0] == certs["encryption"][0])
          cert = (certs["signing"]? || certs["encryption"])[0]
          parsed_metadata[:idp_cert] = cert
          parsed_metadata[:idp_cert_fingerprint] = fingerprint(cert, parsed_metadata[:idp_cert_fingerprint_algorithm]?.try(&.to_s))
        end

        multi = {} of Symbol => Array(String)
        multi[:signing] = certs["signing"] if certs.has_key?("signing")
        multi[:encryption] = certs["encryption"] if certs.has_key?("encryption")
        parsed_metadata[:idp_cert_multi] = multi
      end

      def certificates_has_one(key) : Bool
        (certificates.try(&.[key]?.try(&.size)) || 0) == 1
      end

      private def cert_texts(path) : Array(String)
        @idpsso_descriptor.xpath_nodes(path, SamlMetadata::NAMESPACE).compact_map { |node| Utils.element_text(node) }
      end

      private def attribute_values(path, attribute) : Array(String)
        @idpsso_descriptor.xpath_nodes(path, SamlMetadata::NAMESPACE).compact_map(&.[]?(attribute))
      end

      private def endpoint(path, binding, attribute) : String?
        @idpsso_descriptor.xpath_nodes(path, SamlMetadata::NAMESPACE)
          .find { |node| node["Binding"]? == binding }
          .try(&.[]?(attribute))
      end

      private def first_ranked(values : Array(String), priority) : String?
        return nil if values.empty?

        ranked = case priority
                 when String then [priority]
                 when Array  then priority.map(&.to_s)
                 else             [] of String
                 end
        return values.first if ranked.empty?
        ranked.find { |candidate| values.includes?(candidate) }
      end
    end

    private def merge_parsed_metadata_into(settings : Settings, parsed_metadata : Parsed) : Settings
      parsed_metadata.each { |key, value| settings.set_option(key, value) }
      settings
    end
  end
end
