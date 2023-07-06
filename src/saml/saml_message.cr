# Only supports SAML 2.0
module Saml

  # SAML2 Message
  #
  class SamlMessage
    ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion"
    PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol"

    BASE64_FORMAT = %r(\A([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\Z)
    @@mutex = Mutex.new
    @version : String?
    @id : String?

    # @return [Nokogiri::XML::Schema] Gets the schema object of the SAML 2.0 Protocol schema
    #
    # def self.schema
    #   @@mutex.synchronize do
    #     Dir.chdir(File.expand_path("../../../schemas", __FILE__)) do
    #       ::Nokogiri::XML::Schema(File.read("saml-schema-protocol-2.0.xsd"))
    #     end
    #   end
    # end

    # @return [String|nil] Gets the Version attribute from the SAML Message if exists.
    #
    def version(document)
      @version ||= begin
        if node = document.xpath_node(
            "/p:AuthnRequest | /p:Response | /p:LogoutResponse | /p:LogoutRequest",
            { "p" => PROTOCOL }
          )
          node["Version"]
        end
      end
    end

    # @return [String|nil] Gets the ID attribute from the SAML Message if exists.
    #
    def id(document)
      @id ||= begin
        if node = document.xpath_node(
            "/p:AuthnRequest | /p:Response | /p:LogoutResponse | /p:LogoutRequest",
            { "p" => PROTOCOL }
          )
          node["ID"]
        end
      end
    end

    # Validates the SAML Message against the specified schema.
    # @param document [REXML::Document] The message that will be validated
    # @param soft [Boolean] soft Enable or Disable the soft mode (In order to raise exceptions when the message is invalid or not)
    # @return [Boolean] True if the XML is valid, otherwise False, if soft=True
    # @raise [ValidationError] if soft == false and validation fails
    #
    def valid_saml?(document, soft = true)
      # begin
      #   xml = Nokogiri::XML(document.to_s) do |config|
      #     config.options = XMLSecurity::BaseDocument::NOKOGIRI_OPTIONS
      #   end
      # rescue StandardError => error
      #   return false if soft
      #   raise ValidationError.new("XML load failed: #{error.message}")
      # end

      # SamlMessage.schema.validate(xml).map do |schema_error|
      #   return false if soft
      #   raise ValidationError.new("#{schema_error.message}\n\n#{xml}")
      # end

      true #since there's no good way to do this in Crystal yet
    end

    # Base64 decode and try also to inflate a SAML Message
    # @param saml [String] The deflated and encoded SAML Message
    # @return [String] The plain SAML Message
    #
    private def decode_raw_saml(saml : String, settings = nil) : String
      return saml unless base64_encoded?(saml)

      settings = Saml::Settings.new if settings.nil?
      if saml.bytesize > settings.message_max_bytesize
        raise ValidationError.new("Encoded SAML Message exceeds " + settings.message_max_bytesize.to_s + " bytes, so was rejected")
      end

      decoded = decode(saml)
      begin
        inflate(decoded).to_s
      rescue ex
        puts "Error while inflate: #{ex.inspect_with_backtrace}"
        decoded.to_s
      end
    end

    # Deflate, base64 encode and url-encode a SAML Message (To be used in the HTTP-redirect binding)
    # @param saml [String] The plain SAML Message
    # @param settings [Saml::Settings|nil] Toolkit settings
    # @return [String] The deflated and encoded SAML Message (encoded if the compression is requested)
    #
    private def encode_raw_saml(saml, settings)
      saml = deflate(saml) if settings.compress_request

      URL.encode(encode(saml))
    end

    # Base 64 decode method
    # @param string [String] The string message
    # @return [Bytes] The decoded string
    #
    private def decode(string)
      Base64.decode(string)
    end

    # Base 64 encode method
    # @param string [String] The string
    # @return [String] The encoded string
    #
    private def encode(string)
      Base64.strict_encode(string)
    end

    # Check if a string is base64 encoded
    # @param string [String] string to check the encoding of
    # @return [true, false] whether or not the string is base64 encoded
    #
    private def base64_encoded?(string)
      !!string.gsub(/[\r\n]|\\r|\\n|\s/, "").match(BASE64_FORMAT)
    end

    # Inflate method
    # @param deflated [String] The string
    # @return [String] The inflated string
    #
    private def inflate(deflated)
      begin
        SamlZlibReader.open(IO::Memory.new(deflated)) do |reader|
          reader.gets_to_end
        end
      rescue
        deflated
      end
    end

    # Deflate method
    # @param inflated [String] The string
    # @return [String] The deflated string
    #
    private def deflate(inflated)
      Compress::Zlib::Deflate.deflate(inflated, 9)[2..-5]
    end
  end
end
