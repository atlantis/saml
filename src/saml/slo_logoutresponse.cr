# Only supports SAML 2.0
module Saml
  # SAML2 Logout Response (SLO IdP initiated, Builder)
  #
  class SloLogoutresponse < SamlMessage
    # Logout Response ID
    property uuid : String
    getter logout_url : String?

    def initialize
      @uuid = Saml::Utils.uuid
    end

    def response_id : String
      @uuid
    end

    # Creates the Logout Response URL.
    # @param request_id [String] The ID of the LogoutRequest this answers (InResponseTo)
    # @param logout_message [String] The StatusMessage
    # @param logout_status_code [String] The StatusCode
    # @raise [SettingError] when no IdP SLO URL is set
    def create(settings : Settings, request_id : String? = nil, logout_message : String? = nil,
               params : Hash = {} of String => String?, logout_status_code : String? = nil) : String
      url = settings.idp_slo_response_service_url || settings.idp_slo_service_url
      raise SettingError.new "Invalid settings, idp_slo_service_url is not set!" if url.nil? || url.empty?

      response_params = create_params(settings, request_id, logout_message, params, logout_status_code)
      params_prefix = url.includes?('?') ? "&" : "?"
      saml_response = Saml::Utils.url_encode(response_params.delete("SAMLResponse"))
      query = "#{params_prefix}SAMLResponse=#{saml_response}"
      response_params.each do |key, value|
        query += "&#{key}=#{Saml::Utils.url_encode(value)}"
      end
      @logout_url = url + query
    end

    # Creates the GET parameters for the logout response.
    def create_params(settings : Settings, request_id : String? = nil, logout_message : String? = nil,
                      params : Hash = {} of String => String?, logout_status_code : String? = nil) : Hash(String, String)
      extra = {} of String => String
      params.each do |key, value|
        next if value.nil? && key.to_s == "RelayState"
        extra[key.to_s] = value.to_s
      end
      relay_state = extra["RelayState"]?

      response = create_logout_response_xml_doc(settings, request_id, logout_message, logout_status_code).to_s
      Saml::Log.debug { "Created SLO Logout Response: #{response}" }

      base64_response = encode(settings.compress_response ? deflate(response) : response)
      response_params = {"SAMLResponse" => base64_response}

      if settings.idp_slo_service_binding == Utils::BINDINGS[:redirect] && settings.security[:logout_responses_signed]? == true &&
         (sp_key = settings.get_sp_key)
        sig_alg = settings.security[:signature_method]?.to_s
        extra["SigAlg"] = sig_alg
        url_string = Saml::Utils.build_query({
          type:        "SAMLResponse",
          data:        base64_response,
          relay_state: relay_state,
          sig_alg:     sig_alg,
        })
        extra["Signature"] = encode(sp_key.sign(XMLSecurity::BaseDocument.algorithm(sig_alg), url_string))
      end

      extra.each { |key, value| response_params[key] = value }
      response_params
    end

    # Creates the SAMLResponse document.
    def create_logout_response_xml_doc(settings : Settings, request_id : String? = nil, logout_message : String? = nil,
                                       logout_status_code : String? = nil) : XMLSecurity::Document
      document = create_xml_document(settings, request_id, logout_message, logout_status_code)
      sign_document(document, settings)
    end

    def create_xml_document(settings : Settings, request_id : String? = nil, logout_message : String? = nil,
                            status_code : String? = nil) : XMLSecurity::Document
      time = Time.utc.to_s("%Y-%m-%dT%H:%M:%SZ")

      response_doc = XMLSecurity::Document.new("samlp:LogoutResponse", {"xmlns:samlp" => PROTOCOL, "xmlns:saml" => ASSERTION})
      response_doc.uuid = uuid
      root = response_doc.root.not_nil!

      destination = settings.idp_slo_response_service_url || settings.idp_slo_service_url

      root["ID"] = uuid
      root["IssueInstant"] = time
      root["Version"] = "2.0"
      root["InResponseTo"] = request_id unless request_id.nil?
      root["Destination"] = destination unless destination.nil? || destination.empty?

      if sp_entity_id = settings.sp_entity_id
        root.add_element("saml:Issuer").text = sp_entity_id
      end

      status = root.add_element("samlp:Status")
      status.add_element("samlp:StatusCode", {"Value" => status_code || "urn:oasis:names:tc:SAML:2.0:status:Success"})
      status.add_element("samlp:StatusMessage").text = logout_message || "Successfully Signed Out"

      response_doc
    end

    def sign_document(document : XMLSecurity::Document, settings : Settings) : XMLSecurity::Document
      if settings.idp_slo_service_binding == Utils::BINDINGS[:post] && settings.security[:logout_responses_signed]? == true
        private_key = settings.get_sp_key
        cert = settings.get_sp_cert
        if private_key && cert
          document.sign_document(private_key, cert, settings.security[:signature_method]?.try(&.to_s), settings.security[:digest_method]?.try(&.to_s))
        end
      end

      document
    end
  end
end
