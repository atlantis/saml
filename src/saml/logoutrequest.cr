# Only supports SAML 2.0

module Saml

  # SAML2 Logout Request (SLO SP initiated, Builder)
  #
  class Logoutrequest < SamlMessage

    # Logout Request ID
    property :uuid

    @name_id : String?

    # Initializes the Logout Request. A Logoutrequest Object that is an extension of the SamlMessage class.
    # Asigns an ID, a random uuid.
    #
    def initialize
      @uuid = Saml::Utils.uuid
    end

    def request_id
      @uuid
    end

    # Creates the Logout Request string.
    # @param settings [Saml::Settings|nil] Toolkit settings
    # @param params [Hash] Some extra parameters to be added in the GET for example the RelayState
    # @return [String] Logout Request string that includes the SAMLRequest
    #
    def create(settings, params = {} of Symbol => String)
      params = create_params(settings, params)
      params_prefix = (settings.idp_slo_service_url =~ /\?/) ? "&" : "?"
      saml_request = Saml::Utils.url_encode(params.delete("SAMLRequest"))
      request_params = "#{params_prefix}SAMLRequest=#{saml_request}"
      params.each_pair do |key, value|
        request_params << "&#{key}=#{Saml::Utils.url_encode(value.to_s)}"
      end
      raise SettingError.new "Invalid settings, idp_slo_service_url is not set!" if settings.idp_slo_service_url.nil? || settings.idp_slo_service_url.empty?
      @logout_url = settings.idp_slo_service_url + request_params
    end

    # Creates the Get parameters for the logout request.
    # @param settings [Saml::Settings|nil] Toolkit settings
    # @param params [Hash] Some extra parameters to be added in the GET for example the RelayState
    # @return [Hash] Parameters
    #
    def create_params(settings, params = {} of Symbol => String)
      # The method expects :RelayState but sometimes we get 'RelayState' instead.
      # Based on the HashWithIndifferentAccess value in Rails we could experience
      # conflicts so this line will solve them.
      relay_state = params["RelayState"] || params["RelayState"]

      if relay_state.nil?
        params.delete(:RelayState)
        params.delete("RelayState")
      end

      request_doc = create_logout_request_xml_doc(settings)
      request_doc.context[:attribute_quote] = :quote if settings.double_quote_xml_attribute_values

      request = ""
      request_doc.write(request)

      Logging.debug "Created SLO Logout Request: #{request}"

      request = deflate(request) if settings.compress_request
      base64_request = encode(request)
      request_params = { "SAMLRequest" => base64_request }

      if settings.idp_slo_service_binding == Utils::BINDINGS[:redirect] && settings.security[:logout_requests_signed] && settings.private_key
        params["SigAlg"] = settings.security[:signature_method].as(String)
        url_string = Saml::Utils.build_query(
          type: "SAMLRequest",
          data: base64_request,
          relay_state: relay_state,
          sig_alg: params["SigAlg"],
        )
        sign_algorithm = XMLSecurity::BaseDocument.algorithm(settings.security[:signature_method].as(String))
        signature = settings.get_sp_key.sign(sign_algorithm, url_string)
        params["Signature"] = encode(signature)
      end

      params.each_pair do |key, value|
        request_params[key] = value.to_s
      end

      request_params
    end

    # Creates the SAMLRequest String.
    # @param settings [Saml::Settings|nil] Toolkit settings
    # @return [String] The SAMLRequest String.
    #
    def create_logout_request_xml_doc(settings)
      document = create_xml_document(settings)
      sign_document(document, settings)
    end

    def create_xml_document(settings)
      time = Time.utc.to_s("%Y-%m-%dT%H:%M:%SZ")

      request_doc = XMLSecurity::Document.new("samlp:LogoutRequest", { "xmlns:samlp" => "urn:oasis:names:tc:SAML:2.0:protocol", "xmlns:saml" => "urn:oasis:names:tc:SAML:2.0:assertion" })
      request_doc.uuid = uuid

      root = request_doc.root
      raise "Could not create LogoutRequest" unless root

      root["ID"] = uuid
      root["IssueInstant"] = time
      root["Version"] = "2.0"
      root["Destination"] = settings.idp_slo_service_url if settings.idp_slo_service_url.presence

      if sp_entity_id = settings.sp_entity_id
        issuer = root.add_element "saml:Issuer"
        issuer.text = sp_entity_id
      end

      nameid = root.add_element "saml:NameID"
      if name_identifier_value = settings.name_identifier_value
        nameid["NameQualifier"] = settings.idp_name_qualifier if settings.idp_name_qualifier
        nameid["SPNameQualifier"] = settings.sp_name_qualifier if settings.sp_name_qualifier
        nameid["Format"] = settings.name_identifier_format if settings.name_identifier_format
        nameid.text = name_identifier_value
      else
        # If no NameID is present in the settings we generate one
        nameid.text = Saml::Utils.uuid
        nameid["Format"] = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
      end

      if sessionindex = settings.sessionindex
        sessionindex_element = root.add_element "samlp:SessionIndex"
        sessionindex_element.text = sessionindex
      end

      request_doc
    end

    def sign_document(document, settings)
      # embed signature
      if settings.idp_slo_service_binding == Utils::BINDINGS[:post] && settings.security[:logout_requests_signed] && settings.private_key && settings.certificate
        if private_key = settings.get_sp_key
          if cert = settings.get_sp_cert
            document.sign_document(private_key, cert, settings.security[:signature_method].as?(String), settings.security[:digest_method])
          else
            raise "No cert"
          end
        else
          raise "No private key"
        end
      end

      document
    end
  end
end
