module Saml
  # SAML2 Auxiliary class
  #
  class Utils
    BINDINGS = {:post     => "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
                :redirect => "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"}
    DSIG            = "http://www.w3.org/2000/09/xmldsig#"
    XENC            = "http://www.w3.org/2001/04/xmlenc#"
    DURATION_FORMAT = %r(^
      (-?)P                       # 1: Duration sign
      (?:
        (?:(\d+)Y)?               # 2: Years
        (?:(\d+)M)?               # 3: Months
        (?:(\d+)D)?               # 4: Days
        (?:T
          (?:(\d+)H)?             # 5: Hours
          (?:(\d+)M)?             # 6: Minutes
          (?:(\d+(?:[.,]\d+)?)S)? # 7: Seconds
        )?
        |
        (\d+)W                    # 8: Weeks
      )
    $)x
    UUID_PREFIX = "_"

    GCM_TAG_LENGTH       =   16
    EVP_CTRL_GCM_SET_TAG = 0x11

    @@prefix = UUID_PREFIX

    # @return [Boolean] True if the certificate's notAfter is in the past.
    def self.is_cert_expired(cert : OpenSSL::X509::Certificate | String) : Bool
      cert = OpenSSL::X509::Certificate.new(cert) if cert.is_a?(String)
      if not_after = cert.not_after
        not_after < Time.utc
      else
        true
      end
    end

    # @return [Boolean] True if the certificate is within its validity period.
    def self.is_cert_active(cert : OpenSSL::X509::Certificate | String) : Bool
      cert = OpenSSL::X509::Certificate.new(cert) if cert.is_a?(String)
      now = Time.utc
      not_before = cert.not_before
      not_after = cert.not_after
      !!(not_before && not_after && not_before <= now && not_after >= now)
    end

    # Form encoding, as Ruby's CGI.escape does.
    def self.url_encode(input : String?) : String
      return "" unless input
      URI.encode_www_form(input)
    end

    def self.url_decode(input : String?) : String
      return "" unless input
      URI.decode_www_form(input)
    end

    # Interprets a ISO8601 duration value relative to a given timestamp.
    # @return [Float64] The new unix timestamp, after the duration is applied.
    def self.parse_duration(duration : String, timestamp : Time | Int = Time.utc) : Float64
      matches = duration.match(DURATION_FORMAT)
      raise ArgumentError.new("Invalid ISO 8601 duration") if matches.nil?

      sign = matches[1]? == "-" ? -1 : 1
      values = (2..8).map { |i| (m = matches[i]?) ? m.tr(",", ".").to_f : 0.0 }
      years, months, days, hours, minutes, seconds, weeks = values

      start = timestamp.is_a?(Time) ? timestamp.to_utc : Time.unix(timestamp.to_i64)
      final = start.shift(years: sign * years.to_i, months: sign * months.to_i)
      final = final.shift(days: sign * ((7 * weeks) + days).to_i)
      final.to_unix + sign * ((hours * 3600) + (minutes * 60) + seconds)
    end

    # Return a properly formatted x509 certificate
    def self.format_cert(cert : String?) : String?
      return cert if cert.nil? || cert.empty? || !cert.ascii_only?

      if cert.scan(/BEGIN CERTIFICATE/).size > 1
        formatted_cert = [] of String
        cert.scan(/-{5}BEGIN CERTIFICATE-{5}[\n\r]?.*?-{5}END CERTIFICATE-{5}[\n\r]?/m) do |c|
          if formatted = format_cert(c[0])
            formatted_cert << formatted
          end
        end
        formatted_cert.join("\n")
      else
        cert = cert.gsub(/\-{5}\s?(BEGIN|END) CERTIFICATE\s?\-{5}/, "")
        cert = cert.gsub(/\s/, "")
        lines = cert.scan(/.{1,64}/).map(&.[0])
        "-----BEGIN CERTIFICATE-----\n#{lines.join("\n")}\n-----END CERTIFICATE-----"
      end
    end

    # Return a properly formatted private key
    def self.format_private_key(key : String?) : String?
      return key if key.nil? || key.empty? || key.includes?('\r')

      rsa_key = key.includes?("RSA PRIVATE KEY")
      key = key.gsub(/\-{5}\s?(BEGIN|END)( RSA)? PRIVATE KEY\s?\-{5}/, "")
      key = key.gsub(/\s/, "")
      lines = key.scan(/.{1,64}/).map(&.[0])
      key_label = rsa_key ? "RSA PRIVATE KEY" : "PRIVATE KEY"
      "-----BEGIN #{key_label}-----\n#{lines.join("\n")}\n-----END #{key_label}-----"
    end

    def self.build_cert_object(cert : String?) : OpenSSL::X509::Certificate?
      return nil if cert.nil? || cert.empty?
      OpenSSL::X509::Certificate.new(format_cert(cert).not_nil!)
    end

    def self.build_private_key_object(private_key : String?) : OpenSSL::PKey::RSA?
      return nil if private_key.nil? || private_key.empty?
      OpenSSL::PKey::RSA.new(format_private_key(private_key).not_nil!)
    end

    # Build the Query String signature that will be used in the HTTP-Redirect binding
    def self.build_query(params) : String
      type, data, relay_state, sig_alg = params[:type], params[:data], params[:relay_state]?, params[:sig_alg]

      url_string = "#{type}=#{url_encode(data)}"
      url_string += "&RelayState=#{url_encode(relay_state)}" if relay_state
      url_string + "&SigAlg=#{url_encode(sig_alg)}"
    end

    # Reconstruct a canonical query string from raw URI-encoded parts, to be used in verifying a signature
    def self.build_query_from_raw_parts(params) : String
      type, raw_data, raw_relay_state, raw_sig_alg = params[:type], params[:raw_data], params[:raw_relay_state]?, params[:raw_sig_alg]

      url_string = "#{type}=#{raw_data}"
      url_string += "&RelayState=#{raw_relay_state}" if raw_relay_state
      url_string + "&SigAlg=#{raw_sig_alg}"
    end

    # Prepare raw GET parameters (build them from normal parameters if not provided).
    def self.prepare_raw_get_params(rawparams : Hash(String, String)?, params : Hash(String, String), lowercase_url_encoding = false) : Hash(String, String)
      rawparams ||= {} of String => String

      %w(SAMLRequest SAMLResponse RelayState SigAlg).each do |key|
        if !rawparams.has_key?(key) && (value = params[key]?)
          rawparams[key] = escape_request_param(value, lowercase_url_encoding)
        end
      end

      rawparams
    end

    def self.escape_request_param(param : String, lowercase_url_encoding) : String
      escaped = url_encode(param)
      lowercase_url_encoding ? escaped.gsub(/%[A-Fa-f0-9]{2}/) { |match| match.downcase } : escaped
    end

    # Validate the Signature parameter sent on the HTTP-Redirect binding.
    # Unsupported SigAlg values are refused.
    def self.verify_signature(params) : Bool
      cert, sig_alg, signature, query_string = params[:cert], params[:sig_alg], params[:signature], params[:query_string]
      return false unless cert && sig_alg && signature && query_string

      digest = XMLSecurity::BaseDocument.strict_digest(sig_alg.to_s, XMLSecurity::BaseDocument::SIGNATURE_ALGORITHMS)
      return false unless digest

      cert.public_key.verify(digest, Base64.decode(signature.to_s), query_string.to_s)
    rescue
      false
    end

    # Build the status error message
    def self.status_error_msg(error_msg : String, raw_status_code : String? = nil, status_message : String? = nil) : String
      unless raw_status_code.nil?
        if raw_status_code.includes? "|"
          printable_code = raw_status_code.split(" | ").map { |code| code.split(":").last }.join(" => ")
        else
          printable_code = raw_status_code.split(":").last
        end
        error_msg += ", was " + printable_code
      end

      error_msg += " -> " + status_message unless status_message.nil?

      error_msg
    end

    # Tries each private key in turn; nil if none decrypts the element.
    def self.decrypt_multi(encrypted_node : XML::Node, private_keys : Array(OpenSSL::PKey::RSA)) : String?
      private_keys.each do |key|
        begin
          if result = decrypt_data(encrypted_node, key)
            return result
          end
        rescue
        end
      end
      nil
    end

    # Obtains the decrypted string from an Encrypted node element in XML
    def self.decrypt_data(encrypted_node : XML::Node, private_key : OpenSSL::PKey::RSA | String) : String?
      private_key = OpenSSL::PKey::RSA.new(private_key) if private_key.is_a?(String)
      ns = {"xenc" => XENC}

      encrypt_data = Saml::XMLUtil.only_node(encrypted_node, "./xenc:EncryptedData", ns)
      return nil unless encrypt_data

      symmetric_key = retrieve_symmetric_key(encrypt_data, private_key)
      return nil unless symmetric_key

      cipher_value = Saml::XMLUtil.only_node(encrypt_data, "./xenc:CipherData/xenc:CipherValue", ns)
      text = Saml::XMLUtil.element_text(cipher_value)
      return nil unless text

      encrypt_method = Saml::XMLUtil.only_node(encrypt_data, "./xenc:EncryptionMethod", ns)
      return nil unless encrypt_method

      plaintext = retrieve_plaintext(Base64.decode(text.gsub(/\s/, "")), symmetric_key, encrypt_method["Algorithm"]?)
      plaintext.is_a?(Bytes) ? String.new(plaintext) : plaintext
    end

    # Obtains the symmetric key from the EncryptedData element
    def self.retrieve_symmetric_key(encrypt_data : XML::Node, private_key : OpenSSL::PKey::RSA) : Bytes?
      ns = {"ds" => DSIG, "xenc" => XENC}
      encrypted_key = Saml::XMLUtil.only_node(encrypt_data, "./ds:KeyInfo/xenc:EncryptedKey", ns)

      if encrypted_key.nil? && (ref = retrieve_symetric_key_reference(encrypt_data)) && !ref.empty?
        encrypted_key = Saml::XMLUtil.only_node(encrypt_data, "//xenc:EncryptedKey[@Id=$id]", ns, {"id" => ref})
      end
      return nil unless encrypted_key

      cipher_value = Saml::XMLUtil.only_node(encrypted_key, "./xenc:CipherData/xenc:CipherValue", ns)
      text = Saml::XMLUtil.element_text(cipher_value)
      return nil unless text

      encrypt_method = Saml::XMLUtil.only_node(encrypted_key, "./xenc:EncryptionMethod", ns)
      return nil unless encrypt_method

      key = retrieve_plaintext(Base64.decode(text.gsub(/\s/, "")), private_key, encrypt_method["Algorithm"]?)
      key.is_a?(Bytes) ? key : nil
    end

    def self.retrieve_symetric_key_reference(encrypt_data : XML::Node) : String?
      encrypt_data.xpath_string(
        "substring-after(./ds:KeyInfo/ds:RetrievalMethod/@URI, '#')",
        {"ds" => DSIG}
      )
    end

    # Obtains the deciphered bytes: block ciphers take a symmetric key, key
    # transport takes the SP's RSA key. Nil for unsupported algorithms or when
    # decryption or the GCM tag check fails.
    def self.retrieve_plaintext(cipher_text : Bytes, symmetric_key : Bytes | String | OpenSSL::PKey::RSA | Nil, algorithm : String?) : Bytes?
      case algorithm
      when "http://www.w3.org/2001/04/xmlenc#tripledes-cbc" then cbc_decrypt("DES-EDE3-CBC", cipher_text, symmetric_key)
      when "http://www.w3.org/2001/04/xmlenc#aes128-cbc"    then cbc_decrypt("AES-128-CBC", cipher_text, symmetric_key)
      when "http://www.w3.org/2001/04/xmlenc#aes192-cbc"    then cbc_decrypt("AES-192-CBC", cipher_text, symmetric_key)
      when "http://www.w3.org/2001/04/xmlenc#aes256-cbc"    then cbc_decrypt("AES-256-CBC", cipher_text, symmetric_key)
      when "http://www.w3.org/2009/xmlenc11#aes128-gcm"     then gcm_decrypt("aes-128-gcm", cipher_text, symmetric_key)
      when "http://www.w3.org/2009/xmlenc11#aes192-gcm"     then gcm_decrypt("aes-192-gcm", cipher_text, symmetric_key)
      when "http://www.w3.org/2009/xmlenc11#aes256-gcm"     then gcm_decrypt("aes-256-gcm", cipher_text, symmetric_key)
      when "http://www.w3.org/2001/04/xmlenc#rsa-1_5"
        rsa_decrypt(cipher_text, symmetric_key, LibCrypto::Padding::PKCS1_PADDING)
      when "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
        rsa_decrypt(cipher_text, symmetric_key, LibCrypto::Padding::PKCS1_OAEP_PADDING)
      end
    rescue
      nil
    end

    private def self.rsa_decrypt(cipher_text : Bytes, key, padding) : Bytes?
      rsa = case key
            when OpenSSL::PKey::RSA then key
            when String             then OpenSSL::PKey::RSA.new(key)
            end
      rsa.try(&.private_decrypt(cipher_text, padding))
    end

    # XML Encryption CBC: IV first, then the data; the last plaintext byte is
    # the padding length.
    private def self.cbc_decrypt(name : String, cipher_text : Bytes, key) : Bytes?
      return nil unless key.is_a?(Bytes) || key.is_a?(String)
      cipher = OpenSSL::Cipher.new(name)
      cipher.decrypt
      iv_len = cipher.iv_len
      return nil if cipher_text.size <= iv_len

      cipher.padding = false
      cipher.key = key.to_slice
      cipher.iv = cipher_text[0, iv_len]

      io = IO::Memory.new
      io.write(cipher.update(cipher_text[iv_len..]))
      io.write(cipher.final)
      plain = io.to_slice

      return nil if plain.empty?
      pad = plain[-1].to_i
      return nil if pad < 1 || pad > cipher.block_size || pad > plain.size
      plain[0, plain.size - pad].dup
    end

    # XML Encryption 1.1 GCM: 12-byte IV, ciphertext, 16-byte tag. The tag is
    # always checked.
    private def self.gcm_decrypt(name : String, cipher_text : Bytes, key) : Bytes?
      return nil unless key.is_a?(Bytes) || key.is_a?(String)
      key = key.to_slice
      iv_len = 12
      return nil if cipher_text.size < iv_len + GCM_TAG_LENGTH

      evp = LibCrypto.saml_evp_get_cipherbyname(name)
      return nil if evp.null?
      ctx = LibCrypto.saml_evp_cipher_ctx_new
      return nil if ctx.null?

      begin
        iv = cipher_text[0, iv_len]
        data = cipher_text[iv_len, cipher_text.size - iv_len - GCM_TAG_LENGTH]
        tag = cipher_text[cipher_text.size - GCM_TAG_LENGTH, GCM_TAG_LENGTH].dup

        return nil if LibCrypto.saml_evp_decrypt_init_ex(ctx, evp, nil, nil, nil) != 1
        return nil if LibCrypto.saml_evp_cipher_ctx_ctrl(ctx, 0x9, iv_len, nil) != 1 # EVP_CTRL_GCM_SET_IVLEN
        return nil if LibCrypto.saml_evp_decrypt_init_ex(ctx, nil, nil, key, iv) != 1

        plain = Bytes.new(data.size + 32)
        plain_len = 0
        return nil if LibCrypto.saml_evp_decrypt_update(ctx, plain, pointerof(plain_len), data, data.size) != 1
        return nil if LibCrypto.saml_evp_cipher_ctx_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LENGTH, tag.to_unsafe.as(Void*)) != 1

        final_len = 0
        return nil if LibCrypto.saml_evp_decrypt_final_ex(ctx, plain.to_unsafe + plain_len, pointerof(final_len)) != 1
        plain[0, plain_len + final_len]
      ensure
        LibCrypto.saml_evp_cipher_ctx_free(ctx)
      end
    end

    def self.set_prefix(value : String)
      @@prefix = value
    end

    def self.prefix : String
      @@prefix
    end

    def self.uuid : String
      "#{@@prefix}#{UUID.random}"
    end

    # Matches two URIs: scheme and host case-insensitively, port, path and
    # query exactly. Falls back to plain string equality when either isn't a URL.
    def self.uri_match?(destination_url : String, settings_url : String) : Bool
      dest_uri = URI.parse(destination_url)
      acs_uri = URI.parse(settings_url)

      dest_scheme, acs_scheme, dest_host, acs_host = dest_uri.scheme, acs_uri.scheme, dest_uri.host, acs_uri.host
      if dest_scheme && acs_scheme && dest_host && acs_host
        dest_scheme.downcase == acs_scheme.downcase &&
          dest_host.downcase == acs_host.downcase &&
          (dest_uri.port || URI.default_port(dest_scheme.downcase)) == (acs_uri.port || URI.default_port(acs_scheme.downcase)) &&
          dest_uri.path == acs_uri.path &&
          dest_uri.query == acs_uri.query
      else
        original_uri_match?(destination_url, settings_url)
      end
    rescue URI::Error
      original_uri_match?(destination_url, settings_url)
    end

    def self.original_uri_match?(destination_url, settings_url) : Bool
      destination_url == settings_url
    end

    # Concatenation of the element's own text and CDATA children (comments and
    # child elements ignored). Nil when no element is given.
    def self.element_text(element : XML::Node?) : String?
      Saml::XMLUtil.element_text(element)
    end
  end
end
