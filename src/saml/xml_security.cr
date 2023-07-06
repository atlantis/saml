# The contents of this file are subject to the terms
# of the Common Development and Distribution License
# (the License). You may not use this file except in
# compliance with the License.
#
# You can obtain a copy of the License at
# https://opensso.dev.java.net/public/CDDLv1.0.html or
# opensso/legal/CDDLv1.0.txt
# See the License for the specific language governing
# permission and limitations under the License.
#
# When distributing Covered Code, include this CDDL
# Header Notice in each file and include the License file
# at opensso/legal/CDDLv1.0.txt.
# If applicable, add the following below the CDDL Header,
# with the fields enclosed by brackets [] replaced by
# your own identifying information:
# "Portions Copyrighted [year] [name of copyright owner]"
#
# $Id: xml_sec.rb,v 1.6 2007/10/24 00:28:41 todddd Exp $
#
# Copyright 2007 Sun Microsystems Inc. All Rights Reserved
# Portions Copyrighted 2007 Todd W Saxton.

module XMLSecurity
  class BaseDocument < XML::Node
    C14N = "http://www.w3.org/2001/10/xml-exc-c14n#"
    DSIG = "http://www.w3.org/2000/09/xmldsig#"
    XML_PARSER_OPTIONS = XML::ParserOptions::RECOVER | XML::ParserOptions::NOERROR | XML::ParserOptions::NOWARNING | XML::ParserOptions::NONET

    def self.canon_algorithm(element)
      if algorithm = element
        if algorithm.is_a?(XML::Node)
          algorithm = element["Algorithm"]?
        end

        case algorithm
        when "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
            "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"
          XML::C14N::Mode::C14N_1_0
        when "http://www.w3.org/2006/12/xml-c14n11",
            "http://www.w3.org/2006/12/xml-c14n11#WithComments"
          XML::C14N::Mode::C14N_1_1
        else
          XML::C14N::Mode::C14N_EXCLUSIVE_1_0
        end
      end
    end

    def self.algorithm(element : XML::Node | String?)

      if algorithm = element
        if algorithm.is_a?(XML::Node)
          algorithm = element["Algorithm"]?
        end

        algorithm = algorithm =~ /(rsa-)?sha(.*?)$/i && $2.to_i
      end

      case algorithm
      when 256 then Digest::SHA256.new
      #when 384 then Digest::SHA384 # not supported in Crystal
      when 512 then Digest::SHA512.new
      else
        Digest::SHA1.new
      end
    end

    def pem_to_der( pem : String )
      self.class.pem_to_der( pem )
    end

    def self.pem_to_der( pem : String )
      pem.gsub(/-----BEGIN (.*?)-----/, "").gsub(/-----END (.*?)-----/, "").gsub(/\s/m, "")
    end

    # DO NOT FORMAT
    def to_s
      self.to_xml(options: XML::SaveOptions::AS_XML)
    end
  end

  class Document < BaseDocument
    RSA_SHA1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
    RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
    RSA_SHA384 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"
    RSA_SHA512 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
    SHA1 = "http://www.w3.org/2000/09/xmldsig#sha1"
    SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256"
    SHA384 = "http://www.w3.org/2001/04/xmldsig-more#sha384"
    SHA512 = "http://www.w3.org/2001/04/xmlenc#sha512"
    ENVELOPED_SIG = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
    INC_PREFIX_LIST = "#default samlp saml ds xs xsi md"

    setter :uuid

    @uuid : String?

    def initialize(tag_name, namespaces  = {} of String => String)
      namespaces_string = namespaces.map { |k,v| "#{k}=\"#{v}\"" }.join(" ")
      super(XML.parse("<#{tag_name}#{ " #{namespaces_string}" if namespaces_string}></#{tag_name}>").to_unsafe)
    end

    def to_xml
      self.to_s
    end

    def uuid
      @uuid ||= begin
        if root = document.root
          root["ID"]?
        end
      end
    end

    #<Signature>
    #<SignedInfo>
    #<CanonicalizationMethod />
    #<SignatureMethod />
    #<Reference>
    #<Transforms>
    #<DigestMethod>
    #<DigestValue>
    #</Reference>
    #<Reference /> etc.
    #</SignedInfo>
    #<SignatureValue />
    #<KeyInfo />
    #<Object />
    #</Signature>
    def sign_document(private_key : OpenSSL::PKey::RSA, certificate : OpenSSL::X509::Certificate | String | Nil, signature_method : String? = RSA_SHA1, digest_method = SHA1)
      # to_xml must avoid formatting
      noko = XML.parse(self.to_xml(options: XML::SaveOptions::AS_XML), XML_PARSER_OPTIONS)

      inclusive_namespaces = INC_PREFIX_LIST.split(" ")

      canon_doc = noko.canonicalize(mode: BaseDocument.canon_algorithm(C14N), inclusive_ns: inclusive_namespaces)

      signature_element = self.add_element("ds:Signature", {"xmlns:ds" => DSIG})
      signed_info_element = signature_element.add_element("ds:SignedInfo")
      signed_info_element.add_element("ds:CanonicalizationMethod", { "Algorithm" => C14N })
      signed_info_element.add_element("ds:SignatureMethod", { "Algorithm" => signature_method })

      # Add Reference
      reference_element = signed_info_element.add_element("ds:Reference", {"URI" => "##{uuid}"})

      # Add Transforms
      transforms_element = reference_element.add_element("ds:Transforms")
      transforms_element.add_element("ds:Transform", {"Algorithm" => ENVELOPED_SIG})
      c14element = transforms_element.add_element("ds:Transform", {"Algorithm" => C14N})
      c14element.add_element("ec:InclusiveNamespaces", {"xmlns:ec" => C14N, "PrefixList" => INC_PREFIX_LIST})

      digest_method_element = reference_element.add_element("ds:DigestMethod", {"Algorithm" => digest_method})

      reference_element.add_element("ds:DigestValue").text = compute_digest(canon_doc, BaseDocument.algorithm(digest_method_element))

      # add SignatureValue - to_xml must avoid formatting
      noko_sig_element = XML.parse(signature_element.to_xml(options: XML::SaveOptions::AS_XML), XML_PARSER_OPTIONS)

      if noko_signed_info_element = noko_sig_element.xpath_node("//ds:Signature/ds:SignedInfo", {"ds" => DSIG})
        canon_string = noko_signed_info_element.parent.not_nil!.canonicalize(mode: BaseDocument.canon_algorithm(C14N))
      else
        raise "No SignedInfo found in document"
      end

      signature = compute_signature(private_key, BaseDocument.algorithm(signature_method), canon_string)
      signature_element.add_element("ds:SignatureValue").text = signature

      # add KeyInfo
      key_info_element       = signature_element.add_element("ds:KeyInfo")
      x509_element           = key_info_element.add_element("ds:X509Data")
      x509_cert_element      = x509_element.add_element("ds:X509Certificate")
      if certificate.is_a?(String)
        certificate = OpenSSL::X509::Certificate.new(certificate)
      end
      x509_cert_element.text = pem_to_der(certificate.to_pem).gsub(/\n/, "")

      # move the signature
      if r = self.root.not_nil!.xpath_node("/*")
        if (issuer_element = r.xpath_node("//samlp:LogoutRequest/*", {"saml" => "urn:oasis:names:tc:SAML:2.0:assertion", "samlp" => Saml::Response::PROTOCOL})) && issuer_element.name == "saml:Issuer"
          result = issuer_element.add_next_sibling signature_element
        elsif first_child = r.children.first?
          first_child.add_prev_sibling signature_element
        else
          r.add_child signature_element
        end
      end
    end

    protected def compute_signature(private_key : OpenSSL::PKey::RSA, signature_algorithm, document)
      Base64.strict_encode(private_key.sign(signature_algorithm, document))
    end

    protected def compute_digest(document, digest_algorithm)
      digest = digest_algorithm
      digest << document
      Base64.strict_encode(digest.final)
    end
  end

  class SignedDocument < BaseDocument
    include Saml::ErrorHandling

    setter signed_element_id : String?

    @working_copy : XML::Node? = nil

    def initialize(response, errors = [] of String)
      super(XML.parse(response.to_s, XML_PARSER_OPTIONS).to_unsafe)
      @error_messages = errors
    end

    def signed_element_id
      @signed_element_id ||= extract_signed_element_id
    end

    def format_certificate(cert_text : String?) : String?
      return nil unless cert_text

      # memory error possible unless base64 newlines are respected!
      if cert_text.starts_with?("-----BEGIN CERTIFICATE-----")
        cert_text = cert_text.gsub("-----BEGIN CERTIFICATE-----", "").gsub("-----END CERTIFICATE-----", "").gsub(/\s/m, "")
      end

      "-----BEGIN CERTIFICATE-----\n#{Base64.encode(Base64.decode(cert_text)).strip}\n-----END CERTIFICATE-----"
    end

    def load_cert( cert_text : String? ) : OpenSSL::X509::Certificate?
      if formatted = format_certificate( cert_text )
        begin
          return OpenSSL::X509::Certificate.new(formatted)
        rescue _e : OpenSSL::X509::CertificateError
        end
      end

      nil
    end

    def validate_document(idp_cert_fingerprint, soft = true, options = {} of Symbol => String | OpenSSL::X509::Certificate)
      # get cert from response
      if cert_element = self.xpath_node("//ds:X509Certificate", { "ds" => DSIG })
        if base64_cert = Saml::Utils.element_text(cert_element)
          #cert_text = Base64.decode_string(base64_cert)
          unless cert = load_cert(base64_cert)
            return append_error("Couldn't load certificate from document", soft)
          end

          if fingeralg = options[:fingerprint_alg]?.as?(String)
            fingerprint_alg = BaseDocument.algorithm(fingeralg)
          else
            fingerprint_alg = Digest::SHA1.new
          end
          fingerprint_alg << Base64.decode( pem_to_der( cert.to_pem ) )
          fingerprint = fingerprint_alg.hexfinal

          # check cert matches registered idp cert
          if fingerprint != idp_cert_fingerprint.gsub(/[^a-zA-Z0-9]/, "").downcase
            return append_error("Fingerprint mismatch", soft)
          end
        else
          return append_error("No cert element", soft)
        end
      else
        case raw_cert = options[:cert]?
        when OpenSSL::X509::Certificate
          base64_cert = Base64.encode(raw_cert.to_pem)
        when String
          base64_cert = raw_cert
        else
          if soft
            return false
          else
            return append_error("Certificate element missing in response (ds:X509Certificate) and not cert provided at settings", soft)
          end
        end
      end

      validate_signature(base64_cert, soft)
    end

    def validate_document_with_cert(idp_cert, soft = true)
      # get cert from response
      cert_element = self.xpath_node(
        "//ds:X509Certificate",
        { "ds" => DSIG }
      )

      if cert_element
        if cert_text = Saml::Utils.element_text(cert_element)
          unless cert = load_cert(cert_text)
            return append_error("Document Certificate Error", soft)
          end

          # check saml response cert matches provided idp cert
          if idp_cert.to_pem == cert.to_pem
            base64_cert = Base64.encode(cert.to_pem)
          else
            return append_error("Certificate of the Signature element does not match provided certificate", soft)
          end
        else
          return append_error("Couldn't find text in cert element", soft)
        end
      else
        base64_cert = Base64.encode(idp_cert.to_pem)
      end

      if cert = base64_cert
        validate_signature(cert, true)
      else
        append_error("Couldn't find cert element", soft)
      end
    end

    def validate_signature(base64_cert, soft = true)
      # create a copy document - important to use options that do not change formatting!
      if (document = XML.parse(self.to_xml(options: XML::SaveOptions::AS_XML), XML_PARSER_OPTIONS)) && (@working_copy ||= XML.parse(self.to_s).root)

        # get signature node
        sig_element = @working_copy.not_nil!.xpath_node(
          "//ds:Signature",
          { "ds" => DSIG }
        )

        # signature method
        if sig_alg_value = sig_element.try(&.xpath_node(
            "./ds:SignedInfo/ds:SignatureMethod",
            { "ds" => DSIG }
          ))
          signature_algorithm = BaseDocument.algorithm(sig_alg_value)
        else
          return append_error("Could't find SignatureMethod node", soft)
        end

        # get signature
        signature = if base64_signature = sig_element.try(&.xpath_node("./ds:SignatureValue",{ "ds" => DSIG }))
          if scrubbed_text = Saml::Utils.element_text(base64_signature)
            Base64.decode(scrubbed_text)
          end
        end

        # canonicalization method
        canon_algorithm = BaseDocument.canon_algorithm sig_element.try(&.xpath_node(
          "./ds:SignedInfo/ds:CanonicalizationMethod",
          { "ds" => DSIG },
        ))

        if noko_sig_element = document.xpath_node("//ds:Signature", { "ds" => DSIG })
          if noko_signed_info_element = noko_sig_element.xpath_node("./ds:SignedInfo", { "ds" => DSIG })
            if dirty_hack = noko_sig_element.canonicalize(mode: canon_algorithm).to_s.match(/<ds:SignedInfo.*<\/ds:SignedInfo>/m)
              canon_string = dirty_hack[0]
            else
              return append_error("Couldn't cannonicalize SignedInfo element", soft)
            end
          else
            return append_error("Couldn't find SignedInfo element", soft)
          end
        else
          return append_error("Couldn't find Signature node", soft)
        end

        noko_sig_element.unlink

        # get inclusive namespaces
        inclusive_namespaces = extract_inclusive_namespaces

        # check digests
        if ref = sig_element.try(&.xpath_node("//ds:Reference", { "ds" => DSIG }))
          if hashed_element = document.xpath_node("//*[@ID=$id]", nil, { "id" => extract_signed_element_id })
            canon_algorithm = BaseDocument.canon_algorithm ref.try(&.xpath_node(
              "//ds:CanonicalizationMethod",
              { "ds" => DSIG }
            ))

            canon_algorithm = process_transforms(ref, canon_algorithm)

            if method_node = ref.xpath_node("//ds:DigestMethod",{ "ds" => DSIG })
              digest_algorithm = BaseDocument.algorithm(method_node)

              # have to make sure to disable formatting!
              if referenced_element = XML.parse("<root>#{hashed_element.to_xml(options: XML::SaveOptions::AS_XML)}</root>")
                if referenced_element_canonical_content = referenced_element.canonicalize(mode: canon_algorithm, inclusive_ns: inclusive_namespaces).try &.to_s
                  referenced_element_canonical_content = referenced_element_canonical_content.gsub("<root>", "").gsub("</root>", "").strip

                  digest_algorithm << referenced_element_canonical_content
                  hash = digest_algorithm.final

                  encoded_digest_value = ref.try(&.xpath_node("//ds:DigestValue",{ "ds" => DSIG }))
                  if encoded_text = Saml::Utils.element_text(encoded_digest_value)
                    digest_value = Base64.decode(encoded_text)
                  end
                end
              end
            else
              return append_error("Couldn't find Reference target by ID", soft)
            end
          else
            return append_error("Couldn't find DigestMethod element", soft)
          end
        else
          return append_error("Couldn't find Reference element", soft)
        end

        unless digests_match?(hash, digest_value)
          return append_error("Digest mismatch", soft)
        end

        unless signature
          return append_error("Missing signature", soft)
        end

        # get certificate object
        unless cert = load_cert(base64_cert)
          return append_error("Couldn't load X509 certificate", soft)
        end

        # verify signature
        unless cert.public_key.verify(digest: signature_algorithm, signature: signature, data: canon_string)
          return append_error("Key validation error", soft)
        end
      else
        return append_error("Couln't get a copy of the document", soft)
      end

      return true
    end

    private def process_transforms(ref, canon_algorithm)
      transforms = ref.try(&.xpath_nodes(
        "//ds:Transforms/ds:Transform",
        { "ds" => DSIG }
      )) || [] of XML::Node

      transforms.each do |transform_element|
        if transform_element.attributes && transform_element.attributes["Algorithm"]
          algorithm = transform_element.attributes["Algorithm"]
          case algorithm
          when "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
               "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"
            canon_algorithm = XML::C14N::Mode::C14N_1_0
          when "http://www.w3.org/2006/12/xml-c14n11",
               "http://www.w3.org/2006/12/xml-c14n11#WithComments"
            canon_algorithm = XML::C14N::Mode::C14N_1_1
          when "http://www.w3.org/2001/10/xml-exc-c14n#",
               "http://www.w3.org/2001/10/xml-exc-c14n#WithComments"
            canon_algorithm = XML::C14N::Mode::C14N_EXCLUSIVE_1_0
          end
        end
      end

      canon_algorithm
    end

    private def digests_match?(hash, digest_value)
      hash == digest_value
    end

    private def extract_signed_element_id
      reference_element = self.xpath_node(
        "//ds:Signature/ds:SignedInfo/ds:Reference",
        { "ds" => DSIG }
      )

      return nil if reference_element.nil?

      sei = reference_element["URI"][1..-1]
      if sei.nil?
        if node = reference_element.parent.try(&.parent).try(&.parent)
          if id = node["ID"]
            return id
          end
        end
      else
        sei
      end
    end

    private def extract_inclusive_namespaces
      element = self.xpath_node(
        "//ec:InclusiveNamespaces",
        { "ec" => C14N }
      )
      if element
        prefix_list = element.attributes["PrefixList"].text
        prefix_list.split(" ")
      else
        [] of String
      end
    end

    # TODO: limit to just tests?
    def extract_inclusive_namespaces_for_test
      extract_inclusive_namespaces
    end
  end
end
