module Saml
  # XSD validation with libxml2's schema API. The schemas are compiled into the
  # binary and loaded from a private temporary directory once, so nothing is
  # read from the network or from wherever the shard's source happened to be.
  module Schema
    FILES = {
      "saml-schema-protocol-2.0.xsd"            => {{ read_file("#{__DIR__}/../schemas/saml-schema-protocol-2.0.xsd") }},
      "saml-schema-assertion-2.0.xsd"           => {{ read_file("#{__DIR__}/../schemas/saml-schema-assertion-2.0.xsd") }},
      "saml-schema-metadata-2.0.xsd"            => {{ read_file("#{__DIR__}/../schemas/saml-schema-metadata-2.0.xsd") }},
      "saml-schema-authn-context-2.0.xsd"       => {{ read_file("#{__DIR__}/../schemas/saml-schema-authn-context-2.0.xsd") }},
      "saml-schema-authn-context-types-2.0.xsd" => {{ read_file("#{__DIR__}/../schemas/saml-schema-authn-context-types-2.0.xsd") }},
      "sstc-metadata-attr.xsd"                  => {{ read_file("#{__DIR__}/../schemas/sstc-metadata-attr.xsd") }},
      "sstc-saml-attribute-ext.xsd"             => {{ read_file("#{__DIR__}/../schemas/sstc-saml-attribute-ext.xsd") }},
      "sstc-saml-metadata-algsupport-v1.0.xsd"  => {{ read_file("#{__DIR__}/../schemas/sstc-saml-metadata-algsupport-v1.0.xsd") }},
      "sstc-saml-metadata-ui-v1.0.xsd"          => {{ read_file("#{__DIR__}/../schemas/sstc-saml-metadata-ui-v1.0.xsd") }},
      "xenc-schema.xsd"                         => {{ read_file("#{__DIR__}/../schemas/xenc-schema.xsd") }},
      "xml.xsd"                                 => {{ read_file("#{__DIR__}/../schemas/xml.xsd") }},
      "xmldsig-core-schema.xsd"                 => {{ read_file("#{__DIR__}/../schemas/xmldsig-core-schema.xsd") }},
    }

    PROTOCOL = "saml-schema-protocol-2.0.xsd"
    METADATA = "saml-schema-metadata-2.0.xsd"

    @@schemas = {} of String => Void*
    @@mutex = Mutex.new

    # Errors from validating *document* against the named schema (empty when valid).
    def self.validate(document : XML::Node, name : String = PROTOCOL) : Array(String)
      schema = load(name)
      errors = [] of String
      ctxt = LibSamlXML.xmlSchemaNewValidCtxt(schema)
      raise "Couldn't create a schema validation context" if ctxt.null?

      begin
        LibSamlXML.xmlSchemaSetValidStructuredErrors(ctxt, ->collect_error(Void*, LibXML::Error*), Box.box(errors))
        result = LibSamlXML.xmlSchemaValidateDoc(ctxt, document.to_unsafe.value.doc)
        errors << "Schema validation failed (#{result})" if result != 0 && errors.empty?
      ensure
        LibSamlXML.xmlSchemaFreeValidCtxt(ctxt)
      end

      errors
    end

    # :nodoc:
    def self.collect_error(data : Void*, error : LibXML::Error*) : Nil
      message = error.null? || error.value.message.null? ? "Unknown schema error" : String.new(error.value.message).chomp
      Box(Array(String)).unbox(data) << message
    end

    private def self.load(name : String) : Void*
      @@mutex.synchronize do
        @@schemas[name] ||= parse(name)
      end
    end

    private def self.parse(name : String) : Void*
      dir = File.join(Dir.tempdir, "saml-schemas-#{Random::Secure.hex(8)}")
      Dir.mkdir(dir, 0o700)
      begin
        FILES.each { |file, content| File.write(File.join(dir, file), content, perm: 0o600) }

        errors = [] of String
        ctxt = LibSamlXML.xmlSchemaNewParserCtxt(File.join(dir, name))
        raise "Couldn't create a schema parser context" if ctxt.null?
        begin
          LibSamlXML.xmlSchemaSetParserStructuredErrors(ctxt, ->collect_error(Void*, LibXML::Error*), Box.box(errors))
          schema = LibSamlXML.xmlSchemaParse(ctxt)
          raise "Couldn't load schema #{name}: #{errors.join("; ")}" if schema.null?
          schema
        ensure
          LibSamlXML.xmlSchemaFreeParserCtxt(ctxt)
        end
      ensure
        FileUtils.rm_rf(dir)
      end
    end
  end
end
