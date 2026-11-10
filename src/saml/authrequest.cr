# Only supports SAML 2.0
module Saml
  # SAML2 Authentication. AuthNRequest (SSO SP initiated, Builder)
  #
  class Authrequest < SamlMessage
    # AuthNRequest ID
    property uuid : String
    getter login_url : String?

    def initialize
      @uuid = Saml::Utils.uuid
    end

    def request_id : String
      @uuid
    end

    # Creates the AuthNRequest URL (the IdP SSO URL with the SAMLRequest and
    # any extra parameters, such as RelayState, in the query).
    # @raise [SettingError] when idp_sso_service_url isn't set
    def create(settings : Settings, params : Hash = {} of String => String?) : String
      sso_url = settings.idp_sso_service_url
      raise SettingError.new "Invalid settings, idp_sso_service_url is not set!" if sso_url.nil? || sso_url.empty?

      request_params = create_params(settings, params)
      params_prefix = sso_url.includes?('?') ? "&" : "?"
      saml_request = Saml::Utils.url_encode(request_params.delete("SAMLRequest"))
      query = "#{params_prefix}SAMLRequest=#{saml_request}"
      request_params.each do |key, value|
        query += "&#{key}=#{Saml::Utils.url_encode(value)}"
      end
      @login_url = sso_url + query
    end

    # Creates the GET parameters for the request: SAMLRequest, plus SigAlg and
    # Signature when redirect requests are signed, plus *params*.
    def create_params(settings : Settings, params : Hash = {} of String => String?) : Hash(String, String)
      extra = {} of String => String
      params.each do |key, value|
        next if value.nil? && key.to_s == "RelayState"
        extra[key.to_s] = value.to_s
      end
      relay_state = extra["RelayState"]?

      request = create_authentication_xml_doc(settings).to_s
      Saml::Log.debug { "Created AuthnRequest: #{request}" }

      base64_request = encode(settings.compress_request ? deflate(request) : request)
      request_params = {"SAMLRequest" => base64_request}

      if settings.idp_sso_service_binding == Utils::BINDINGS[:redirect] && settings.security[:authn_requests_signed]? == true &&
         (sp_key = settings.get_sp_key)
        sig_alg = settings.security[:signature_method]?.to_s
        extra["SigAlg"] = sig_alg
        url_string = Saml::Utils.build_query({
          type:        "SAMLRequest",
          data:        base64_request,
          relay_state: relay_state,
          sig_alg:     sig_alg,
        })
        signature = sp_key.sign(XMLSecurity::BaseDocument.algorithm(sig_alg), url_string)
        extra["Signature"] = encode(signature)
      end

      extra.each { |key, value| request_params[key] = value }
      request_params
    end

    # Creates the SAMLRequest document (signed when the POST binding asks for it).
    def create_authentication_xml_doc(settings : Settings) : XMLSecurity::Document
      document = create_xml_document(settings)
      sign_document(document, settings)
    end

    def create_xml_document(settings : Settings) : XMLSecurity::Document
      time = Time.utc.to_s("%Y-%m-%dT%H:%M:%SZ")

      request_doc = XMLSecurity::Document.new("samlp:AuthnRequest", {"xmlns:samlp" => PROTOCOL, "xmlns:saml" => ASSERTION})
      request_doc.uuid = uuid
      root = request_doc.root.not_nil!

      root["ID"] = uuid
      root["IssueInstant"] = time
      root["Version"] = "2.0"
      if (destination = settings.idp_sso_service_url) && !destination.empty?
        root["Destination"] = destination
      end
      root["IsPassive"] = settings.passive.to_s unless settings.passive.nil?
      root["ProtocolBinding"] = settings.protocol_binding.to_s unless settings.protocol_binding.nil?
      root["AttributeConsumingServiceIndex"] = settings.attributes_index.to_s unless settings.attributes_index.nil?
      root["ForceAuthn"] = settings.force_authn.to_s unless settings.force_authn.nil?
      if acs_url = settings.assertion_consumer_service_url
        root["AssertionConsumerServiceURL"] = acs_url
      end

      if sp_entity_id = settings.sp_entity_id
        root.add_element("saml:Issuer").text = sp_entity_id
      end

      if name_identifier_value_requested = settings.name_identifier_value_requested
        subject = root.add_element("saml:Subject")
        nameid = subject.add_element("saml:NameID", {"Format" => settings.name_identifier_format})
        nameid.text = name_identifier_value_requested
        subject.add_element("saml:SubjectConfirmation", {"Method" => "urn:oasis:names:tc:SAML:2.0:cm:bearer"})
      end

      if format = settings.name_identifier_format
        root.add_element("samlp:NameIDPolicy", {"AllowCreate" => "true", "Format" => format})
      end

      if settings.authn_context || settings.authn_context_decl_ref
        comparison = settings.authn_context_comparison || "exact"
        requested_context = root.add_element("samlp:RequestedAuthnContext", {"Comparison" => comparison})

        class_refs = case context = settings.authn_context
                     when String then [context]
                     when Array  then context
                     else             [] of String
                     end
        class_refs.each do |class_ref|
          requested_context.add_element("saml:AuthnContextClassRef").text = class_ref
        end

        decl_refs = case decl = settings.authn_context_decl_ref
                    when String then [decl]
                    when Array  then decl
                    else             [] of String
                    end
        decl_refs.each do |decl_ref|
          requested_context.add_element("saml:AuthnContextDeclRef").text = decl_ref
        end
      end

      request_doc
    end

    def sign_document(document : XMLSecurity::Document, settings : Settings) : XMLSecurity::Document
      if settings.idp_sso_service_binding == Utils::BINDINGS[:post] && settings.security[:authn_requests_signed]? == true
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
