# Only supports SAML 2.0
module Saml
  # SAML2 Metadata. XML Metadata Builder
  #
  class Metadata
    METADATA  = "urn:oasis:names:tc:SAML:2.0:metadata"
    ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion"
    DSIG      = "http://www.w3.org/2000/09/xmldsig#"
    # Kept as REXML wrote it so existing consumers see the same bytes.
    XML_DECLARATION = "<?xml version='1.0' encoding='UTF-8'?>"

    # Return SP metadata based on the settings.
    # @param settings [Saml::Settings] Toolkit settings
    # @param pretty_print [Boolean] Pretty print or not the response
    #                               (No pretty print if you gonna validate the signature)
    # @param valid_until [Time] Metadata's valid time
    # @param cache_duration [Integer] Duration of the cache in seconds
    # @return [String] XML Metadata of the Service Provider
    def generate(settings : Settings, pretty_print = false, valid_until : Time? = nil, cache_duration : Int? = nil) : String
      meta_doc = create_document(settings, valid_until, cache_duration)
      root = meta_doc.root.not_nil!
      sp_sso = add_sp_sso_element(root, settings)
      add_sp_certificates(sp_sso, settings)
      add_sp_service_elements(sp_sso, settings)
      add_extras(root, settings)
      embed_signature(meta_doc, settings)
      output_xml(meta_doc, pretty_print)
    end

    protected def create_document(settings, valid_until, cache_duration) : XMLSecurity::Document
      namespaces = {"xmlns:md" => METADATA}
      namespaces["xmlns:saml"] = ASSERTION if settings.attribute_consuming_service.configured?

      meta_doc = XMLSecurity::Document.new("md:EntityDescriptor", namespaces)
      root = meta_doc.root.not_nil!
      root["ID"] = Saml::Utils.uuid
      if sp_entity_id = settings.sp_entity_id
        root["entityID"] = sp_entity_id
      end
      root["validUntil"] = valid_until.to_utc.to_s("%Y-%m-%dT%H:%M:%SZ") if valid_until
      root["cacheDuration"] = "PT#{cache_duration}S" if cache_duration
      meta_doc
    end

    protected def add_sp_sso_element(root, settings) : XML::Node
      root.add_element("md:SPSSODescriptor", {
        "protocolSupportEnumeration" => "urn:oasis:names:tc:SAML:2.0:protocol",
        "AuthnRequestsSigned"        => (settings.security[:authn_requests_signed]? == true).to_s,
        "WantAssertionsSigned"       => (settings.security[:want_assertions_signed]? == true).to_s,
      })
    end

    # Add KeyDescriptor if messages will be signed / encrypted
    # with SP certificate, and new SP certificate if any
    protected def add_sp_certificates(sp_sso, settings)
      [settings.get_sp_cert, settings.get_sp_cert_new].each do |sp_cert|
        next unless sp_cert
        cert_text = Base64.strict_encode(sp_cert.to_der)
        add_key_descriptor(sp_sso, "signing", cert_text)
        add_key_descriptor(sp_sso, "encryption", cert_text) if settings.security[:want_assertions_encrypted]? == true
      end

      sp_sso
    end

    private def add_key_descriptor(sp_sso, use, cert_text)
      kd = sp_sso.add_element("md:KeyDescriptor", {"use" => use})
      ki = kd.add_element("ds:KeyInfo", {"xmlns:ds" => DSIG})
      ki.add_element("ds:X509Data").add_element("ds:X509Certificate").text = cert_text
    end

    protected def add_sp_service_elements(sp_sso, settings)
      if slo_url = settings.single_logout_service_url
        sp_sso.add_element("md:SingleLogoutService", {
          "Binding"          => settings.single_logout_service_binding,
          "Location"         => slo_url,
          "ResponseLocation" => slo_url,
        })
      end

      if format = settings.name_identifier_format
        sp_sso.add_element("md:NameIDFormat").text = format
      end

      if acs_url = settings.assertion_consumer_service_url
        sp_sso.add_element("md:AssertionConsumerService", {
          "Binding"   => settings.assertion_consumer_service_binding,
          "Location"  => acs_url,
          "isDefault" => "true",
          "index"     => "0",
        })
      end

      service = settings.attribute_consuming_service
      if service.configured?
        sp_acs = sp_sso.add_element("md:AttributeConsumingService", {"isDefault" => "true", "index" => service.index})
        sp_acs.add_element("md:ServiceName", {"xml:lang" => "en"}).text = service.name.to_s
        service.attributes.each do |attribute|
          sp_req_attr = sp_acs.add_element("md:RequestedAttribute", {
            "NameFormat"   => attribute[:name_format]?.try(&.to_s),
            "Name"         => attribute[:name]?.try(&.to_s),
            "FriendlyName" => attribute[:friendly_name]?.try(&.to_s),
            "isRequired"   => (attribute[:is_required]? || false).to_s,
          })
          case values = attribute[:attribute_value]?
          when Nil
          when Array
            values.each { |value| sp_req_attr.add_element("saml:AttributeValue").text = value.to_s }
          else
            sp_req_attr.add_element("saml:AttributeValue").text = values.to_s
          end
        end
      end

      sp_sso
    end

    # can be overridden in subclass
    protected def add_extras(root, _settings)
      root
    end

    protected def embed_signature(meta_doc, settings)
      return unless settings.security[:metadata_signed]? == true

      private_key = settings.get_sp_key
      cert = settings.get_sp_cert
      return unless private_key && cert

      meta_doc.sign_document(private_key, cert, settings.security[:signature_method]?.try(&.to_s), settings.security[:digest_method]?.try(&.to_s))
    end

    protected def output_xml(meta_doc, pretty_print) : String
      root = meta_doc.root.not_nil!
      if pretty_print
        # So IdP administrators can easily see what the SP supports
        XML_DECLARATION + "\n" + root.to_xml(indent: 1, options: XML::SaveOptions::FORMAT | XML::SaveOptions::NO_DECL | XML::SaveOptions::AS_XML)
      else
        XML_DECLARATION + root.to_xml(options: XML::SaveOptions::NO_DECL | XML::SaveOptions::AS_XML)
      end
    end
  end
end
