# Only supports SAML 2.0
module Saml
  # SAML2 Authentication. AuthNRequest (SSO SP initiated, Builder)

  class Authrequest < SamlMessage

    # AuthNRequest ID
    property :uuid

    # Initializes the AuthNRequest. An Authrequest Object that is an extension of the SamlMessage class.
    # Asigns an ID, a random uuid.
    #
    def initialize
      @uuid = Saml::Utils.uuid
    end

    def request_id
      @uuid
    end

    # Creates the AuthNRequest string.
    # @param settings [Saml::Settings|nil] Toolkit settings
    # @param params [Hash] Some extra parameters to be added in the GET for example the RelayState
    # @return [String] AuthNRequest string that includes the SAMLRequest
    #
    def create(settings, params = {} of String => String)
      params = create_params(settings, params )
      params_prefix = (settings.idp_sso_service_url =~ /\?/) ? "&" : "?"
      saml_request = URL.encode(params.delete("SAMLRequest"))
      request_params = "#{params_prefix}SAMLRequest=#{saml_request}"
      params.each_pair do |key, value|
        request_params << "&#{key}=#{URL.encode(value.to_s)}"
      end
      raise SettingError.new "Invalid settings, idp_sso_service_url is not set!" if settings.idp_sso_service_url.nil? || settings.idp_sso_service_url.empty?
      @login_url = settings.idp_sso_service_url + request_params
    end

    # Creates the Get parameters for the request.
    # @param settings [Saml::Settings|nil] Toolkit settings
    # @param params [Hash] Some extra parameters to be added in the GET for example the RelayState
    # @return [Hash] Parameters
    #
    def create_params(settings, params = {} of String => String)
      # The method expects :RelayState but sometimes we get 'RelayState' instead.
      # Based on the HashWithIndifferentAccess value in Rails we could experience
      # conflicts so this line will solve them.
      relay_state = params[:RelayState] || params["RelayState"]

      if relay_state.nil?
        params.delete(:RelayState)
        params.delete("RelayState")
      end

      request_doc = create_authentication_xml_doc(settings)
      request_doc.context[:attribute_quote] = :quote if settings.double_quote_xml_attribute_values

      request = ""
      request_doc.write(request)

      Logging.debug "Created AuthnRequest: #{request}"

      request = deflate(request) if settings.compress_request
      base64_request = encode(request)
      request_params = { "SAMLRequest" => base64_request }

      if settings.idp_sso_service_binding == Utils::BINDINGS[:redirect] && settings.security[:authn_requests_signed] && settings.private_key
        params["SigAlg"] = settings.security[:signature_method]
        url_string = Saml::Utils.build_query(
          type: "SAMLRequest",
          data: base64_request,
          relay_state: relay_state,
          sig_alg: params["SigAlg"],
        )
        sign_algorithm = XMLSecurity::BaseDocument.new.algorithm(settings.security[:signature_method])
        signature = settings.get_sp_key.sign(sign_algorithm.new, url_string)
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
    def create_authentication_xml_doc(settings : Settings)
      document = create_xml_document(settings)
      sign_document(document, settings)
    end

    def create_xml_document(settings)
      time = Time.utc.to_s("%Y-%m-%dT%H:%M:%SZ")

      request_doc = XMLSecurity::Document.new("samlp:AuthnRequest", { "xmlns:samlp" => "urn:oasis:names:tc:SAML:2.0:protocol", "xmlns:saml" => "urn:oasis:names:tc:SAML:2.0:assertion" })
      if root = request_doc.root
        request_doc.uuid = uuid


        root["ID"] = uuid
        root["IssueInstant"] = time
        root["Version"] = "2.0"
        root["Destination"] = settings.idp_sso_service_url if settings.idp_sso_service_url.presence
        root["IsPassive"] = settings.passive unless settings.passive.nil?
        root["ProtocolBinding"] = settings.protocol_binding unless settings.protocol_binding.nil?
        root["AttributeConsumingServiceIndex"] = settings.attributes_index unless settings.attributes_index.nil?
        root["ForceAuthn"] = settings.force_authn unless settings.force_authn.nil?

        # Conditionally defined elements based on settings
        if settings.assertion_consumer_service_url != nil
          root.attributes["AssertionConsumerServiceURL"] = settings.assertion_consumer_service_url
        end
        if sp_entity_id = settings.sp_entity_id
          issuer = root.add_element "saml:Issuer"
          issuer.text = sp_entity_id
        end

        if name_identifier_value_requested = settings.name_identifier_value_requested
          subject = root.add_element "saml:Subject"

          nameid = subject.add_element "saml:NameID"
          nameid.attributes["Format"] = settings.name_identifier_format if settings.name_identifier_format
          nameid.text = name_identifier_value_requested

          subject_confirmation = subject.add_element "saml:SubjectConfirmation"
          subject_confirmation.attributes["Method"] = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
        end

        if settings.name_identifier_format != nil
          root.add_element "samlp:NameIDPolicy", {
            # Might want to make AllowCreate a setting?
            "AllowCreate" => "true",
            "Format" => settings.name_identifier_format,
          }
        end

        if settings.authn_context || settings.authn_context_decl_ref
          if settings.authn_context_comparison != nil
            comparison = settings.authn_context_comparison
          else
            comparison = "exact"
          end

          requested_context = root.add_element "samlp:RequestedAuthnContext", {
            "Comparison" => comparison,
          }

          authn_contexts_class_refs = case authn_context = settings.authn_context
          when String
            [authn_context]
          when Array(String)
            authn_context
          end

          if authn_contexts_class_refs
            authn_contexts_class_refs.each do |authn_context_class_ref|
              if class_ref = requested_context.add_element( "saml:AuthnContextClassRef" )
                if val = authn_context_class_ref.as?(String)
                  class_ref.text = val
                end
              end
            end
          end

          if settings.authn_context_decl_ref != nil
            authn_contexts_decl_refs = settings.authn_context_decl_ref.is_a?(Array(String)) ? settings.authn_context_decl_ref.as(Array(String)) : [settings.authn_context_decl_ref]
            authn_contexts_decl_refs.each do |authn_context_decl_ref|
              decl_ref = requested_context.add_element "saml:AuthnContextDeclRef"
              decl_ref.text = authn_context_decl_ref if authn_context_decl_ref
            end
          end
        end
      end

      request_doc
    end

    def sign_document(document, settings)
      if settings.idp_sso_service_binding == Utils::BINDINGS[:post] && settings.security[:authn_requests_signed] && settings.private_key && settings.certificate
        if private_key = settings.get_sp_key
          if cert = settings.get_sp_cert
            document.sign_document(private_key, cert, settings.security[:signature_method], settings.security[:digest_method])
          else
            raise "No certificate found"
          end
        else
          raise "No private key found"
        end
      end

      document
    end
  end
end
