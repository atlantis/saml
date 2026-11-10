# Only supports SAML 2.0
module Saml
  # SAML2 Logout Request (SLO SP initiated, Builder)
  #
  class Logoutrequest < SamlMessage
    # Logout Request ID
    property uuid : String
    getter logout_url : String?

    def initialize
      @uuid = Saml::Utils.uuid
    end

    def request_id : String
      @uuid
    end

    # Creates the Logout Request URL.
    # @raise [SettingError] when idp_slo_service_url isn't set
    def create(settings : Settings, params : Hash = {} of String => String?) : String
      slo_url = settings.idp_slo_service_url
      raise SettingError.new "Invalid settings, idp_slo_service_url is not set!" if slo_url.nil? || slo_url.empty?

      request_params = create_params(settings, params)
      params_prefix = slo_url.includes?('?') ? "&" : "?"
      saml_request = Saml::Utils.url_encode(request_params.delete("SAMLRequest"))
      query = "#{params_prefix}SAMLRequest=#{saml_request}"
      request_params.each do |key, value|
        query += "&#{key}=#{Saml::Utils.url_encode(value)}"
      end
      @logout_url = slo_url + query
    end

    # Creates the GET parameters for the logout request.
    def create_params(settings : Settings, params : Hash = {} of String => String?) : Hash(String, String)
      extra = {} of String => String
      params.each do |key, value|
        next if value.nil? && key.to_s == "RelayState"
        extra[key.to_s] = value.to_s
      end
      relay_state = extra["RelayState"]?

      request = create_logout_request_xml_doc(settings).to_s
      Saml::Log.debug { "Created SLO Logout Request: #{request}" }

      base64_request = encode(settings.compress_request ? deflate(request) : request)
      request_params = {"SAMLRequest" => base64_request}

      if settings.idp_slo_service_binding == Utils::BINDINGS[:redirect] && settings.security[:logout_requests_signed]? == true &&
         (sp_key = settings.get_sp_key)
        sig_alg = settings.security[:signature_method]?.to_s
        extra["SigAlg"] = sig_alg
        url_string = Saml::Utils.build_query({
          type:        "SAMLRequest",
          data:        base64_request,
          relay_state: relay_state,
          sig_alg:     sig_alg,
        })
        extra["Signature"] = encode(sp_key.sign(XMLSecurity::BaseDocument.algorithm(sig_alg), url_string))
      end

      extra.each { |key, value| request_params[key] = value }
      request_params
    end

    # Creates the SAMLRequest document.
    def create_logout_request_xml_doc(settings : Settings) : XMLSecurity::Document
      document = create_xml_document(settings)
      sign_document(document, settings)
    end

    def create_xml_document(settings : Settings) : XMLSecurity::Document
      time = Time.utc.to_s("%Y-%m-%dT%H:%M:%SZ")

      request_doc = XMLSecurity::Document.new("samlp:LogoutRequest", {"xmlns:samlp" => PROTOCOL, "xmlns:saml" => ASSERTION})
      request_doc.uuid = uuid
      root = request_doc.root.not_nil!

      root["ID"] = uuid
      root["IssueInstant"] = time
      root["Version"] = "2.0"
      if (destination = settings.idp_slo_service_url) && !destination.empty?
        root["Destination"] = destination
      end

      if sp_entity_id = settings.sp_entity_id
        root.add_element("saml:Issuer").text = sp_entity_id
      end

      if name_identifier_value = settings.name_identifier_value
        nameid = root.add_element("saml:NameID", {
          "NameQualifier"   => settings.idp_name_qualifier,
          "SPNameQualifier" => settings.sp_name_qualifier,
          "Format"          => settings.name_identifier_format,
        })
        nameid.text = name_identifier_value
      else
        # If no NameID is present in the settings we generate one
        nameid = root.add_element("saml:NameID", {"Format" => "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"})
        nameid.text = Saml::Utils.uuid
      end

      if sessionindex = settings.sessionindex
        root.add_element("samlp:SessionIndex").text = sessionindex
      end

      request_doc
    end

    def sign_document(document : XMLSecurity::Document, settings : Settings) : XMLSecurity::Document
      if settings.idp_slo_service_binding == Utils::BINDINGS[:post] && settings.security[:logout_requests_signed]? == true
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
