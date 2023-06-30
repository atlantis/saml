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

    def self.algorithm(element : XML::Node | String)
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

    def initialize(xml = "")
      super(XML.parse(xml, XML_PARSER_OPTIONS).to_unsafe)
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
    def sign_document(private_key : OpenSSL::PKey::RSA, certificate : OpenSSL::X509::Certificate | String | Nil, signature_method = RSA_SHA1, digest_method = SHA1)
      noko = XML.parse(self.to_s, XML_PARSER_OPTIONS)

      signature_element = XML.build_fragment do |xml|
        xml.element("ds", "Signature", DSIG, {} of String => String) do
          xml.element("ds:SignedInfo") do
            xml.element("ds:CanonicalizationMethod", { "Algorithm" => C14N })
            xml.element("ds:SignatureMethod", { "Algorithm" => signature_method })

            # Add Reference
            xml.element("ds:Reference", { "URI" => "##{uuid}" }) do
              xml.element("ds:DigestMethod", { "Algorithm" => digest_method })

              inclusive_namespaces = INC_PREFIX_LIST.split(" ")
              canon_doc = noko.canonicalize(mode: BaseDocument.canon_algorithm(C14N), inclusive_ns: inclusive_namespaces)
              xml.element("ds:DigestValue") do
                xml.text compute_digest(canon_doc, BaseDocument.algorithm(digest_method.to_s))
              end
            end
          end
        end
      end

      # signature_element = REXML::Element.new("ds:Signature").add_namespace("ds", DSIG)
      # signed_info_element = signature_element.add_element("ds:SignedInfo")
      # signed_info_element.add_element("ds:CanonicalizationMethod", { "Algorithm" => C14N })
      # signed_info_element.add_element("ds:SignatureMethod", { "Algorithm" => signature_method })

      transforms_element = XML.build_fragment do |xml|
        xml.element("ds:Transforms") do
          xml.element("ds:Transform", { "Algorithm" => ENVELOPED_SIG })
          xml.element("ds:Transform", { "Algorithm" => C14N }) do
            xml.element("ec:InclusiveNamespaces", { "xmlns:ec" => C14N, "PrefixList" => INC_PREFIX_LIST })
          end
        end
      end

      # Add Transforms
      # transforms_element = reference_element.add_element("ds:Transforms")
      # transforms_element.add_element("ds:Transform", { "Algorithm" => ENVELOPED_SIG })
      # c14element = transforms_element.add_element("ds:Transform", { "Algorithm" => C14N })
      # c14element.add_element("ec:InclusiveNamespaces", { "xmlns:ec" => C14N, "PrefixList" => INC_PREFIX_LIST })

      # add SignatureValue
      noko_sig_element = XML.parse(signature_element, XML_PARSER_OPTIONS)

      cert_object = case certificate
      when String
        OpenSSL::X509::Certificate.new(certificate)
      when OpenSSL::X509::Certificate
        certificate
      else
        raise "Missing certificate"
      end

      if noko_signed_info_element = noko_sig_element.xpath_node("//ds:Signature/ds:SignedInfo", {"ds" => DSIG})
        canon_string = noko_signed_info_element.canonicalize(mode: BaseDocument.canon_algorithm(C14N))
        signature = compute_signature(private_key, BaseDocument.algorithm(signature_method.to_s), canon_string)
        noko_signed_info_element.add_element("ds:SignatureValue").text = signature

        # add KeyInfo
        key_info_element = noko_signed_info_element.add_element("ds:KeyInfo")
        x509_element = key_info_element.add_element("ds:X509Data")
        x509_cert_element = x509_element.add_element("ds:X509Certificate")
        x509_cert_element.text = Base64.strict_encode(cert_object.public_key.to_der)
      else
        raise "No SignedInfo element found in the signature"
      end

      # add the signature - TODO: see if it's important to insert it in these places
      # if issuer_element = noko.xpath_node("//saml:Issuer")
      #   root.insert_after(issuer_element, signature_element)
      # elsif first_child = root.children[0]
      #   root.insert_before(first_child, signature_element)
      # else
        self << XML.parse(signature_element)
      # end
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

    def validate_document(idp_cert_fingerprint, soft = true, options = {} of Symbol => String | OpenSSL::X509::Certificate)
      # get cert from response
      cert_element = self.xpath_node(
        "//ds:X509Certificate",
        { "ds" => DSIG }
      )

      if cert_element
        if base64_cert = Saml::Utils.element_text(cert_element)
          cert_text = Base64.decode_string(base64_cert)
          begin
            cert = OpenSSL::X509::Certificate.new(cert_text)
          rescue _e : OpenSSL::X509::CertificateError
            return append_error("Document Certificate Error", soft)
          end

          if fingeralg = options[:fingerprint_alg].as?(String)
            fingerprint_alg = BaseDocument.algorithm(fingeralg)
          else
            fingerprint_alg = OpenSSL::Digest.new("SHA1")
          end
          fingerprint_alg << cert.public_key.to_der
          fingerprint = fingerprint_alg.hexfinal

          # check cert matches registered idp cert
          if fingerprint != idp_cert_fingerprint.gsub(/[^a-zA-Z0-9]/, "").downcase
            return append_error("Fingerprint mismatch", soft)
          end
        else
          return append_error("No cert element", soft)
        end
      else
        case raw_cert = options[:cert]
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
        if base64_cert = Saml::Utils.element_text(cert_element)
          cert_text = Base64.decode_string(base64_cert)
          begin
            cert = OpenSSL::X509::Certificate.new(cert_text)
          rescue _e : OpenSSL::X509::CertificateError
            return append_error("Document Certificate Error", soft)
          end

          # check saml response cert matches provided idp cert
          if idp_cert.to_pem != cert.to_pem
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
        return append_error("Couldn't find cert element", soft)
      end
    end

    def validate_signature(base64_cert, soft = true)
      document = XML.parse(self.to_s, XML_PARSER_OPTIONS)

      # create a copy document
      @working_copy ||= XML.parse(self.to_s).root

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

      noko_sig_element = document.try(&.xpath_node("//ds:Signature", { "ds" => DSIG }))
      noko_signed_info_element = noko_sig_element.try(&.xpath_node("./ds:SignedInfo", { "ds" => DSIG }))

      canon_string = noko_signed_info_element.try(&.canonicalize(mode: canon_algorithm))
      noko_sig_element.try(&.unlink)

      # get inclusive namespaces
      inclusive_namespaces = extract_inclusive_namespaces

      # check digests
      ref = sig_element.try(&.xpath_node("//ds:Reference", { "ds" => DSIG }))

      hashed_element = document.xpath_node("//*[@ID=$id]", nil, { "id" => extract_signed_element_id })

      canon_algorithm = BaseDocument.canon_algorithm ref.try(&.xpath_node(
        "//ds:CanonicalizationMethod",
        { "ds" => DSIG }
      ))

      canon_algorithm = process_transforms(ref, canon_algorithm)

      canon_hashed_element = hashed_element.try(&.canonicalize(mode: canon_algorithm, inclusive_ns: inclusive_namespaces))

      if (method_node = ref.try(&.xpath_node("//ds:DigestMethod",{ "ds" => DSIG }))) && (digest_algorithm = BaseDocument.algorithm(method_node))
        if hashed = canon_hashed_element
          digest_algorithm << hashed
          hash = digest_algorithm.final
          encoded_digest_value = ref.try(&.xpath_node("//ds:DigestValue",{ "ds" => DSIG }))
          if encoded_text = Saml::Utils.element_text(encoded_digest_value)
            digest_value = Base64.decode(encoded_text)
          end
        end
      else
        return append_error("Couldn't find DigestMethod element", soft)
      end

      unless digests_match?(hash, digest_value)
        return append_error("Digest mismatch", soft)
      end

      # get certificate object
      if bcert = base64_cert
        cert_text = Base64.decode_string(bcert)
        cert = OpenSSL::X509::Certificate.new(cert_text)

        # verify signature
        unless (sig = signature && (cannonical = canon_string)) && cert.public_key.verify(signature_algorithm, sig, cannonical)
          return append_error("Key validation error", soft)
        end
      else
        return append_error("Couln't get base64 cert", soft)
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
