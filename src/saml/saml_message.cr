require "file_utils"

# Only supports SAML 2.0
module Saml
  # SAML2 Message
  #
  class SamlMessage
    ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion"
    PROTOCOL  = "urn:oasis:names:tc:SAML:2.0:protocol"

    BASE64_FORMAT = %r(\A([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\Z)

    @version : String?
    @id : String?

    # @return [String|nil] Gets the Version attribute from the SAML Message if exists.
    def version(document) : String?
      @version ||= begin
        if node = document.xpath_node(
             "/p:AuthnRequest | /p:Response | /p:LogoutResponse | /p:LogoutRequest",
             {"p" => PROTOCOL}
           )
          node["Version"]?
        end
      end
    end

    # @return [String|nil] Gets the ID attribute from the SAML Message if exists.
    def id(document) : String?
      @id ||= begin
        if node = document.xpath_node(
             "/p:AuthnRequest | /p:Response | /p:LogoutResponse | /p:LogoutRequest",
             {"p" => PROTOCOL}
           )
          node["ID"]?
        end
      end
    end

    # Validates the message against the SAML 2.0 protocol schema.
    # @raise [ValidationError] if soft == false and validation fails
    def valid_saml?(document, soft = true, check_malformed_doc = true) : Bool
      xml = begin
        if document.is_a?(XMLSecurity::SignedDocument)
          raise XMLLoadError.new(document.load_error.not_nil!) unless document.loaded?
          document.xml_document
        elsif document.is_a?(XML::Node)
          document
        else
          XMLUtil.safe_parse(document.to_s)
        end
      rescue error : XMLLoadError
        return false if soft
        raise ValidationError.new("XML load failed: #{error.message}")
      end

      errors = Schema.validate(xml)
      return true if errors.empty?
      return false if soft
      raise ValidationError.new("#{errors.join("\n")}\n\n#{xml}")
    end

    # Base64 decodes and, when it is deflated, inflates a SAML message. Sizes
    # are checked before any regexp or decoding work and again after inflating
    # (CVE-2025-54572, CVE-2025-25293).
    private def decode_raw_saml(saml : String, settings = nil) : String
      settings = Saml::Settings.new if settings.nil?
      max = settings.message_max_bytesize
      if saml.bytesize > max
        raise ValidationError.new("Encoded SAML Message exceeds " + max.to_s + " bytes, so was rejected")
      end

      return saml unless base64_encoded?(saml)

      decoded = decode_bytes(saml)
      message = begin
        inflate(decoded, max)
      rescue ex : ValidationError
        raise ex
      rescue
        String.new(decoded)
      end

      if message.bytesize > max
        raise ValidationError.new("SAML Message exceeds " + max.to_s + " bytes, so was rejected")
      end

      message
    end

    # Deflate, base64 encode and url-encode a SAML Message (To be used in the HTTP-redirect binding)
    private def encode_raw_saml(saml : String, settings) : String
      data = settings.compress_request ? deflate(saml) : saml.to_slice
      Saml::Utils.url_encode(encode(data))
    end

    private def decode(string : String) : String
      String.new(decode_bytes(string))
    end

    private def decode_bytes(string : String) : Bytes
      Base64.decode(string.gsub(/[\r\n]|\\r|\\n|\s/, ""))
    end

    private def encode(string : String | Bytes) : String
      Base64.strict_encode(string)
    end

    # Check if a string is base64 encoded
    private def base64_encoded?(string : String) : Bool
      !!string.gsub(/[\r\n]|\\r|\\n|\s/, "").match(BASE64_FORMAT)
    end

    # Raw deflate (no zlib header), as the redirect binding uses. Stops as
    # soon as the output passes *max* bytes.
    private def inflate(deflated : Bytes, max : Int32 = Int32::MAX) : String
      output = IO::Memory.new
      Compress::Deflate::Reader.open(IO::Memory.new(deflated)) do |reader|
        buffer = Bytes.new(16384)
        while (read = reader.read(buffer)) > 0
          output.write(buffer[0, read])
          if output.size > max
            raise ValidationError.new("SAML Message exceeds " + max.to_s + " bytes, so was rejected")
          end
        end
      end
      output.to_s
    end

    private def deflate(inflated : String) : Bytes
      deflated = IO::Memory.new
      Compress::Deflate::Writer.open(deflated, level: Compress::Deflate::BEST_COMPRESSION) do |writer|
        writer.write(inflated.to_slice)
      end
      deflated.to_slice
    end
  end
end
