module Saml

  # SAML2 Auxiliary class
  #
  class Utils
    @@uuid_generator = UUID

    BINDINGS = { :post => "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
                :redirect => "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" }
    DSIG = "http://www.w3.org/2000/09/xmldsig#"
    XENC = "http://www.w3.org/2001/04/xmlenc#"
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

    # Checks if the x509 cert provided is expired
    #
    # @param cert [Certificate] The x509 certificate
    #
    def self.is_cert_expired(cert)
      if cert.is_a?(String)
        if cert = OpenSSL::X509::Certificate.new(cert)
          return cert.not_nil!.not_after < Time.utc
        else
          raise "Can't parse cert"
        end
      else
        raise "No cert"
      end
    end

    # Interprets a ISO8601 duration value relative to a given timestamp.
    #
    # @param duration [String] The duration, as a string.
    # @param timestamp [Integer] The unix timestamp we should apply the
    #                            duration to. Optional, default to the
    #                            current time.
    #
    # @return [Integer] The new timestamp, after the duration is applied.
    #
    def self.parse_duration(duration, timestamp = Time.utc)
      matches = duration.match(DURATION_FORMAT)

      if matches.nil?
        raise Exception.new("Invalid ISO 8601 duration")
      end

      sign = matches[1] == "-" ? -1 : 1

      durYears, durMonths, durDays, durHours, durMinutes, durSeconds, durWeeks =
        matches[2..8].map { |match| match ? sign * match.tr(",", ".").to_f : 0.0 }

      initial_datetime = Time.at(timestamp).utc.to_datetime
      final_datetime = initial_datetime.next_year(durYears)
      final_datetime = final_datetime.next_month(durMonths)
      final_datetime = final_datetime.next_day((7 * durWeeks) + durDays)
      final_timestamp = final_datetime.to_time.utc.to_i + (durHours * 3600) + (durMinutes * 60) + durSeconds
      return final_timestamp
    end

    # Return a properly formatted x509 certificate
    #
    # @param cert [String] The original certificate
    # @return [String] The formatted certificate
    #
    def self.format_cert(cert)
      # don't try to format an encoded certificate or if is empty or nil
      if cert.responds_to?(:ascii_only?)
        return cert if cert.nil? || cert.not_nil!.empty? || !cert.not_nil!.ascii_only?
      else
        return cert if cert.nil? || cert.not_nil!.empty? || cert.not_nil!.match(/\x0d/)
      end

      if cert.scan(/BEGIN CERTIFICATE/).size > 1
        formatted_cert = [] of String
        cert.scan(/-{5}BEGIN CERTIFICATE-{5}[\n\r]?.*?-{5}END CERTIFICATE-{5}[\n\r]?/m) { |c|
          formatted_cert << format_cert(c[0])
        }
        formatted_cert.join("\n")
      else
        cert = cert.gsub(/\-{5}\s?(BEGIN|END) CERTIFICATE\s?\-{5}/, "")
        cert = cert.gsub(/\r/, "")
        cert = cert.gsub(/\n/, "")
        cert = cert.gsub(/\s/, "")
        cert = cert.scan(/.{1,64}/).map{|r|r[0]}
        cert = cert.join("\n")
        "-----BEGIN CERTIFICATE-----\n#{cert}\n-----END CERTIFICATE-----"
      end
    end

    # Return a properly formatted private key
    #
    # @param key [String] The original private key
    # @return [String] The formatted private key
    #
    def self.format_private_key(key)
      # don't try to format an encoded private key or if is empty
      return key if key.nil? || key.empty? || key.match(/\x0d/)

      # is this an rsa key?
      rsa_key = key.includes?("RSA PRIVATE KEY")
      key = key.gsub(/\-{5}\s?(BEGIN|END)( RSA)? PRIVATE KEY\s?\-{5}/, "")
      key = key.gsub(/\n/, "")
      key = key.gsub(/\r/, "")
      key = key.gsub(/\s/, "")
      key = key.scan(/.{1,64}/).map{|r|r[0]}
      key = key.join("\n")
      key_label = rsa_key ? "RSA PRIVATE KEY" : "PRIVATE KEY"
      "-----BEGIN #{key_label}-----\n#{key}\n-----END #{key_label}-----"
    end

    # Build the Query String signature that will be used in the HTTP-Redirect binding
    # to generate the Signature
    # @param params [Hash] Parameters to build the Query String
    # @option params [String] :type 'SAMLRequest' or 'SAMLResponse'
    # @option params [String] :data Base64 encoded SAMLRequest or SAMLResponse
    # @option params [String] :relay_state The RelayState parameter
    # @option params [String] :sig_alg The SigAlg parameter
    # @return [String] The Query String
    #
    def self.build_query(params)
      type, data, relay_state, sig_alg = [:type, :data, :relay_state, :sig_alg].map { |k| params[k] }

      url_string = "#{type}=#{URL.encode(data)}"
      url_string << "&RelayState=#{URL.encode(relay_state)}" if relay_state
      url_string << "&SigAlg=#{URL.encode(sig_alg)}"
    end

    # Reconstruct a canonical query string from raw URI-encoded parts, to be used in verifying a signature
    #
    # @param params [Hash] Parameters to build the Query String
    # @option params [String] :type 'SAMLRequest' or 'SAMLResponse'
    # @option params [String] :raw_data URI-encoded, base64 encoded SAMLRequest or SAMLResponse, as sent by IDP
    # @option params [String] :raw_relay_state URI-encoded RelayState parameter, as sent by IDP
    # @option params [String] :raw_sig_alg URI-encoded SigAlg parameter, as sent by IDP
    # @return [String] The Query String
    #
    def self.build_query_from_raw_parts(params)
      type, raw_data, raw_relay_state, raw_sig_alg = [:type, :raw_data, :raw_relay_state, :raw_sig_alg].map { |k| params[k] }

      url_string = "#{type}=#{raw_data}"
      url_string << "&RelayState=#{raw_relay_state}" if raw_relay_state
      url_string << "&SigAlg=#{raw_sig_alg}"
    end

    # Prepare raw GET parameters (build them from normal parameters
    # if not provided).
    #
    # @param rawparams [Hash] Raw GET Parameters
    # @param params [Hash] GET Parameters
    # @param lowercase_url_encoding [bool] Lowercase URL Encoding  (For ADFS urlencode compatiblity)
    # @return [Hash] New raw parameters
    #
    def self.prepare_raw_get_params(rawparams, params, lowercase_url_encoding = false)
      rawparams ||= {} of String => String

      if rawparams["SAMLRequest"]?.nil? && !params["SAMLRequest"]?.nil?
        rawparams["SAMLRequest"] = escape_request_param(params["SAMLRequest"], lowercase_url_encoding)
      end
      if rawparams["SAMLResponse"]?.nil? && !params["SAMLResponse"]?.nil?
        rawparams["SAMLResponse"] = escape_request_param(params["SAMLResponse"], lowercase_url_encoding)
      end
      if rawparams["RelayState"]?.nil? && !params["RelayState"]?.nil?
        rawparams["RelayState"] = escape_request_param(params["RelayState"], lowercase_url_encoding)
      end
      if rawparams["SigAlg"]?.nil? && !params["SigAlg"]?.nil?
        rawparams["SigAlg"] = escape_request_param(params["SigAlg"], lowercase_url_encoding)
      end

      rawparams
    end

    def self.escape_request_param(param, lowercase_url_encoding)
      URL.encode(param).tap do |escaped|
        next unless lowercase_url_encoding

        escaped.gsub!(/%[A-Fa-f0-9]{2}/) { |match| match.downcase }
      end
    end

    # Validate the Signature parameter sent on the HTTP-Redirect binding
    # @param params [Hash] Parameters to be used in the validation process
    # @option params [OpenSSL::X509::Certificate] cert The Identity provider public certtificate
    # @option params [String] sig_alg The SigAlg parameter
    # @option params [String] signature The Signature parameter (base64 encoded)
    # @option params [String] query_string The full GET Query String to be compared
    # @return [Boolean] True if the Signature is valid, False otherwise
    #
    def self.verify_signature(params)
      cert, sig_alg, signature, query_string = [:cert, :sig_alg, :signature, :query_string].map { |k| params[k] }
      signature_algorithm = XMLSecurity::BaseDocument.new.algorithm(sig_alg)
      return cert.public_key.verify(signature_algorithm.new, Base64.decode(signature), query_string)
    end

    # Build the status error message
    # @param status_code [String] StatusCode value
    # @param status_message [Strig] StatusMessage value
    # @return [String] The status error message
    def self.status_error_msg(error_msg, raw_status_code = nil, status_message = nil)
      unless raw_status_code.nil?
        if raw_status_code.includes? "|"
          status_codes = raw_status_code.split(" | ")
          values = status_codes.map do |status_code|
            status_code.split(":").last
          end
          printable_code = values.join(" => ")
        else
          printable_code = raw_status_code.split(":").last
        end
        error_msg += ", was " + printable_code
      end

      unless status_message.nil?
        error_msg += " -> " + status_message
      end

      error_msg
    end

    # Obtains the decrypted string from an Encrypted node element in XML
    # @param encrypted_node [XML::Node]     The Encrypted element
    # @param private_key    [OpenSSL::PKey::RSA] The Service provider private key
    # @return [String] The decrypted data
    def self.decrypt_data(encrypted_node : XML::Node, private_key)
      if encrypt_data = encrypted_node.xpath_node(
          "./xenc:EncryptedData",
          { "xenc" => XENC }
        )
        symmetric_key = retrieve_symmetric_key(encrypt_data, private_key)
        if cipher_value = encrypt_data.xpath_node(
            "./xenc:CipherData/xenc:CipherValue",
            { "xenc" => XENC }
          )
          if et = element_text(cipher_value)
            node = Base64.decode(et)
            if encrypt_method = encrypt_data.xpath_node(
                "./xenc:EncryptionMethod",
                { "xenc" => XENC }
              )
              algorithm = encrypt_method["Algorithm"]
              return retrieve_plaintext(node, symmetric_key, algorithm)
            end
          end
        end

        nil
      end
    end

    # Obtains the symmetric key from the EncryptedData element
    # @param encrypt_data [XML::Node]     The EncryptedData element
    # @param private_key [OpenSSL::PKey::RSA] The Service provider private key
    # @return [String] The symmetric key
    def self.retrieve_symmetric_key(encrypt_data : XML::Node, private_key)
      if encrypted_key = encrypt_data.xpath_node(
          "./ds:KeyInfo/xenc:EncryptedKey | ./KeyInfo/xenc:EncryptedKey | //xenc:EncryptedKey[@Id=$id]",
          { "ds" => DSIG, "xenc" => XENC },
          { "id" => self.retrieve_symetric_key_reference(encrypt_data) }
        )

        encrypted_symmetric_key_element = encrypted_key.xpath_node(
          "./xenc:CipherData/xenc:CipherValue",
          {"xenc" => XENC}
        )

        if et = element_text(encrypted_symmetric_key_element)
          cipher_text = Base64.decode(et)
          if encrypt_method = encrypted_key.xpath_node(
              "./xenc:EncryptionMethod",
              {"xenc" => XENC},
            )

            algorithm = encrypt_method["Algorithm"]
            return retrieve_plaintext(cipher_text, private_key, algorithm)
          end
        end
      end

      nil
    end

    def self.retrieve_symetric_key_reference(encrypt_data : XML::Node)
      encrypt_data.xpath_string(
        "substring-after(./ds:KeyInfo/ds:RetrievalMethod/@URI, '#')",
        { "ds" => DSIG }
      )
    end

    # Obtains the deciphered text
    # @param cipher_text [String]   The ciphered text
    # @param symmetric_key [String] The symetric key used to encrypt the text
    # @param algorithm [String]     The encrypted algorithm
    # @return [String] The deciphered text
    def self.retrieve_plaintext(cipher_text, symmetric_key : String | Slice(UInt8) | Nil, algorithm)
      case algorithm
      when "http://www.w3.org/2001/04/xmlenc#tripledes-cbc" then cipher = OpenSSL::Cipher.new("DES-EDE3-CBC")
      when "http://www.w3.org/2001/04/xmlenc#aes128-cbc" then cipher = OpenSSL::Cipher.new("AES-128-CBC")
      when "http://www.w3.org/2001/04/xmlenc#aes192-cbc" then cipher = OpenSSL::Cipher.new("AES-192-CBC")
      when "http://www.w3.org/2001/04/xmlenc#aes256-cbc" then cipher = OpenSSL::Cipher.new("AES-256-CBC")
      when "http://www.w3.org/2009/xmlenc11#aes128-gcm" then auth_cipher = OpenSSL::Cipher.new("AES-128-GCM")
      when "http://www.w3.org/2009/xmlenc11#aes192-gcm" then auth_cipher = OpenSSL::Cipher.new("AES-192-GCM")
      when "http://www.w3.org/2009/xmlenc11#aes256-gcm" then auth_cipher = OpenSSL::Cipher.new("AES-256-GCM")
      when "http://www.w3.org/2001/04/xmlenc#rsa-1_5"
        case symmetric_key
        when OpenSSL::PKey::RSA
          rsa = symmetric_key
        when String
          rsa = OpenSSL::PKey::RSA.new(symmetric_key)
        end
      when "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
        case symmetric_key
        when String
          oaep = OpenSSL::PKey::RSA.new(symmetric_key)
        end
      end

      #put it in decrypt mode
      if c = (cipher || auth_cipher).as?(OpenSSL::Cipher)
        c.decrypt
      end

      if cipher
        if key = symmetric_key
          iv_len = cipher.iv_len
          data = cipher_text[iv_len..-1]
          cipher.padding, cipher.key, cipher.iv = false, key, cipher_text[0..iv_len - 1]

          io = IO::Memory.new
          io.write(cipher.update(data))
          io.write(cipher.final)
          io.rewind

          io.gets_to_end
        else
          return nil
        end
      elsif auth_cipher
        if key = symmetric_key
          iv_len, text_len, tag_len = auth_cipher.iv_len, cipher_text.size, 16
          data = cipher_text[iv_len..text_len - 1 - tag_len]
          auth_cipher.padding = false
          auth_cipher.key = key
          auth_cipher.iv = cipher_text[0..iv_len - 1]
          # auth_cipher.auth_data = ""
          # auth_cipher.auth_tag = cipher_text[text_len - tag_len..-1]
          io = IO::Memory.new
          io.write(auth_cipher.update(data))
          io.write(auth_cipher.final)
          io.rewind

          io.gets_to_end
        else
          return nil
        end
      elsif rsa
        rsa.private_decrypt(cipher_text)
      elsif oaep.is_a?(OpenSSL::PKey::RSA)
        oaep.private_decrypt(cipher_text, LibCrypto::Padding::PKCS1_OAEP_PADDING)
      else
        # epic fail return nil
        nil
      end
    end

    def self.set_prefix(value)
      UUID_PREFIX.replace value
    end

    def self.uuid
      "#{UUID_PREFIX}#{UUID.random}"
    end

    # Given two strings, attempt to match them as URIs using URL parse method.  If they can be parsed,
    # then the fully-qualified domain name and the host should performa a case-insensitive match, per the
    # RFC for URIs.  If URL can not parse the string in to URL pieces, return a boolean match of the
    # two strings.  This maintains the previous functionality.
    # @return [Boolean]
    def self.uri_match?(destination_url : String, settings_url : String)
      dest_uri = URI.parse(destination_url)
      acs_uri = URI.parse(settings_url)

      if dest_uri.scheme.nil? || acs_uri.scheme.nil? || dest_uri.host.nil? || acs_uri.host.nil?
        raise URI::Error.new
      else
        dest_uri.scheme.not_nil!.downcase == acs_uri.scheme.not_nil!.downcase &&
          dest_uri.host.not_nil!.downcase == acs_uri.host.not_nil!.downcase &&
          dest_uri.path == acs_uri.path &&
          dest_uri.query == acs_uri.query
      end
    rescue err : URI::Error
      original_uri_match?(destination_url, settings_url)
    end

    # If URI.parse can't match to valid URL, default back to the original matching service.
    # @return [Boolean]
    def self.original_uri_match?(destination_url, settings_url)
      destination_url == settings_url
    end

    # Given a XML::Node instance, return the concatenation of all child text nodes. Assumes
    # that there all children other than text nodes can be ignored (e.g. comments). If nil is
    # passed, nil will be returned.
    def self.element_text(element)
      #element.texts.map(&.value).join if element
      # TODO: may need to be more robust CDATA, comments, etc
      element.text if element
    end
  end
end
