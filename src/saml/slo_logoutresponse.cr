# Only supports SAML 2.0
module Saml

  # SAML2 Logout Response (SLO SP initiated, Parser)
  #
  class SloLogoutresponse < SamlMessage

    # Logout Response ID
    property :uuid

    # Initializes the Logout Response. A SloLogoutresponse Object that is an extension of the SamlMessage class.
    # Asigns an ID, a random uuid.
    #
    def initialize
      @uuid = Saml::Utils.uuid
    end

    def response_id
      @uuid
    end

    # Creates the Logout Response string.
    # @param settings [Saml::Settings|nil] Toolkit settings
    # @param request_id [String] The ID of the LogoutRequest sent by this SP to the IdP. That ID will be placed as the InResponseTo in the logout response
    # @param logout_message [String] The Message to be placed as StatusMessage in the logout response
    # @param params [Hash] Some extra parameters to be added in the GET for example the RelayState
    # @param logout_status_code [String] The StatusCode to be placed as StatusMessage in the logout response
    # @return [String] Logout Request string that includes the SAMLRequest
    #
    def create(settings, request_id = nil, logout_message = nil, params = {} of Symbol => String, logout_status_code = nil)
      params = create_params(settings, request_id, logout_message, params, logout_status_code)
      params_prefix = (settings.idp_slo_service_url =~ /\?/) ? "&" : "?"
      url = settings.idp_slo_response_service_url || settings.idp_slo_service_url
      saml_response = Saml::Utils.url_encode(params.delete("SAMLResponse"))
      response_params = "#{params_prefix}SAMLResponse=#{saml_response}"
      params.each do |key, value|
        response_params += "&#{key}=#{Saml::Utils.url_encode(value.to_s)}"
      end

      raise SettingError.new "Invalid settings, idp_slo_service_url is not set!" if url.nil? || url.empty?
      @logout_url = url + response_params
    end

    # Creates the Get parameters for the logout response.
    # @param settings [Saml::Settings|nil] Toolkit settings
    # @param request_id [String] The ID of the LogoutRequest sent by this SP to the IdP. That ID will be placed as the InResponseTo in the logout response
    # @param logout_message [String] The Message to be placed as StatusMessage in the logout response
    # @param params [Hash] Some extra parameters to be added in the GET for example the RelayState
    # @param logout_status_code [String] The StatusCode to be placed as StatusMessage in the logout response
    # @return [Hash] Parameters
    #
    def create_params(settings, request_id = nil, logout_message = nil, params = {} of Symbol | String => String, logout_status_code = nil)
      # The method expects :RelayState but sometimes we get 'RelayState' instead.
      # Based on the HashWithIndifferentAccess value in Rails we could experience
      # conflicts so this line will solve them.
      relay_state = params["RelayState"] || params["RelayState"]

      if relay_state.nil?
        params.delete(:RelayState)
        params.delete("RelayState")
      end

      response_doc = create_logout_response_xml_doc(settings, request_id, logout_message, logout_status_code)
      response_doc.context[:attribute_quote] = :quote if settings.double_quote_xml_attribute_values

      response = ""
      response_doc.write(response)

      Logging.debug "Created SLO Logout Response: #{response}"

      response = deflate(response) if settings.compress_response
      base64_response = encode(response)
      response_params = { "SAMLResponse" => base64_response }

      if settings.idp_slo_service_binding == Utils::BINDINGS[:redirect] && settings.security[:logout_responses_signed] && settings.private_key
        params["SigAlg"] = settings.security[:signature_method].as(String)
        url_string = Saml::Utils.build_query(
          type: "SAMLResponse",
          data: base64_response,
          relay_state: relay_state,
          sig_alg: params["SigAlg"],
        )
        sign_algorithm = XMLSecurity::BaseDocument.algorithm(settings.security[:signature_method].as(String))
        signature = settings.get_sp_key.sign(sign_algorithm, url_string)
        params["Signature"] = encode(signature)
      end

      params.each do |key, value|
        response_params[key] = value.to_s
      end

      response_params
    end

    # Creates the SAMLResponse String.
    # @param settings [Saml::Settings|nil] Toolkit settings
    # @param request_id [String] The ID of the LogoutRequest sent by this SP to the IdP. That ID will be placed as the InResponseTo in the logout response
    # @param logout_message [String] The Message to be placed as StatusMessage in the logout response
    # @param logout_status_code [String] The StatusCode to be placed as StatusMessage in the logout response
    # @return [String] The SAMLResponse String.
    #
    def create_logout_response_xml_doc(settings, request_id = nil, logout_message = nil, logout_status_code = nil)
      document = create_xml_document(settings, request_id, logout_message, logout_status_code)
      sign_document(document, settings)
    end

    def create_xml_document(settings, request_id = nil, logout_message = nil, status_code = nil)
      time = Time.utc.to_s("%Y-%m-%dT%H:%M:%SZ")

      response_doc = XMLSecurity::Document.new("samlp:LogoutResponse", { "xmlns:samlp" => "urn:oasis:names:tc:SAML:2.0:protocol", "xmlns:saml" => "urn:oasis:names:tc:SAML:2.0:assertion" })
      response_doc.uuid = uuid

      destination = settings.idp_slo_response_service_url || settings.idp_slo_service_url

      root = response_doc.root.not_nil!
      root.attributes["ID"] = uuid
      root.attributes["IssueInstant"] = time
      root.attributes["Version"] = "2.0"
      root.attributes["InResponseTo"] = request_id unless request_id.nil?
      root.attributes["Destination"] = destination unless destination.nil? || destination.empty?

      if sp_entity_id = settings.sp_entity_id
        issuer = root.add_element "saml:Issuer"
        issuer.text = sp_entity_id
      end

      # add status
      status = root.add_element "samlp:Status"

      # status code
      status_code ||= "urn:oasis:names:tc:SAML:2.0:status:Success"
      status_code_elem = status.add_element "samlp:StatusCode"
      status_code_elem.attributes["Value"] = status_code

      # status message
      logout_message ||= "Successfully Signed Out"
      status_message = status.add_element "samlp:StatusMessage"
      status_message.text = logout_message

      response_doc
    end

    def sign_document(document, settings)
      # embed signature
      if settings.idp_slo_service_binding == Utils::BINDINGS[:post] && settings.private_key && settings.certificate
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
