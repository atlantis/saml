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

    def canon_algorithm(element)
      if algorithm = element
        if algorithm.is_a?(XML::Node)
          algorithm = element["Algorithm"]
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

    def algorithm(element : XML::Node | String)
      if algorithm = element
        if algorithm.is_a?(XML::Node)
          algorithm = element["Algorithm"]
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

    def uuid
      @uuid ||= begin
        document.root.nil? ? nil : document.root.attributes["ID"]
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
    def sign_document(private_key, certificate, signature_method = RSA_SHA1, digest_method = SHA1)
      noko = XML.parse(self.to_s, XML_PARSER_OPTIONS)

      signature_element = XML.build_fragment do |xml|
        xml.element("ds:Signature") do |signature_element|
          signature_element.element("ds:SignedInfo") do |signed_info_element|
            signature_element.element("ds:CanonicalizationMethod", { "Algorithm" => C14N })
            signature_element.element("ds:SignatureMethod", { "Algorithm" => signature_method })

            # Add Reference
            reference_element = signed_info_element.element("ds:Reference", { "URI" => "##{uuid}" })

            digest_method_element = reference_element.element("ds:DigestMethod", { "Algorithm" => digest_method })
            inclusive_namespaces = INC_PREFIX_LIST.split(" ")
            canon_doc = noko.canonicalize(mode: canon_algorithm(C14N), inclusive_ns: inclusive_namespaces)
            reference_element.element("ds:DigestValue") do |digest_value_element|
              digest_value_element.text compute_digest(canon_doc, algorithm(digest_method))
            end
          end
        end
      end

      # signature_element = REXML::Element.new("ds:Signature").add_namespace("ds", DSIG)
      # signed_info_element = signature_element.add_element("ds:SignedInfo")
      # signed_info_element.add_element("ds:CanonicalizationMethod", { "Algorithm" => C14N })
      # signed_info_element.add_element("ds:SignatureMethod", { "Algorithm" => signature_method })

      transforms_element = XML.build_fragment do |xml|
        xml.element("ds:Transforms") do |transforms_element|
          transforms_element.element("ds:Transform", { "Algorithm" => ENVELOPED_SIG })
          transforms_element.element("ds:Transform", { "Algorithm" => C14N }) do |c14element|
            c14element.element("ec:InclusiveNamespaces", { "xmlns:ec" => C14N, "PrefixList" => INC_PREFIX_LIST })
          end
        end
      end

      # Add Transforms
      # transforms_element = reference_element.add_element("ds:Transforms")
      # transforms_element.add_element("ds:Transform", { "Algorithm" => ENVELOPED_SIG })
      # c14element = transforms_element.add_element("ds:Transform", { "Algorithm" => C14N })
      # c14element.add_element("ec:InclusiveNamespaces", { "xmlns:ec" => C14N, "PrefixList" => INC_PREFIX_LIST })

      # add SignatureValue
      noko_sig_element = XML.Parse(signature_element, XML_PARSER_OPTIONS)

      noko_signed_info_element = noko_sig_element.at_xpath("//ds:Signature/ds:SignedInfo", {"ds" => DSIG})
      canon_string = noko_signed_info_element.canonicalize(mode: canon_algorithm(C14N))

      signature = compute_signature(private_key, algorithm(signature_method).new, canon_string)
      signature_element.add_element("ds:SignatureValue").text = signature

      # add KeyInfo
      key_info_element = signature_element.add_element("ds:KeyInfo")
      x509_element = key_info_element.add_element("ds:X509Data")
      x509_cert_element = x509_element.add_element("ds:X509Certificate")
      if certificate.is_a?(String)
        certificate = OpenSSL::X509::Certificate.new(certificate)
      end
      x509_cert_element.text = Base64.encode(certificate.to_der).gsub(/\n/, "")

      # add the signature
      issuer_element = elements["//saml:Issuer"]
      if issuer_element
        root.insert_after(issuer_element, signature_element)
      elsif first_child = root.children[0]
        root.insert_before(first_child, signature_element)
      else
        root.add_element(signature_element)
      end
    end

    protected def compute_signature(private_key, signature_algorithm, document)
      Base64.encode(private_key.sign(signature_algorithm, document)).gsub(/\n/, "")
    end

    protected def compute_digest(document, digest_algorithm)
      digest = digest_algorithm.digest(document)
      Base64.encode(digest).strip
    end
  end

  class SignedDocument < BaseDocument
    include Saml::ErrorHandling

    setter :signed_element_id

    @working_copy : XML::Node? = nil

    def initialize(response, errors = [] of String)
      super(XML.parse(response.to_s, XML_PARSER_OPTIONS).to_unsafe)
      @error_messages = errors
    end

    def signed_element_id
      @signed_element_id ||= extract_signed_element_id
    end

    def validate_document(idp_cert_fingerprint, soft = true, options = {} of Symbol => String)
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

          if options[:fingerprint_alg]
            fingerprint_alg = XMLSecurity::BaseDocument.new.algorithm(options[:fingerprint_alg]).new
          else
            fingerprint_alg = OpenSSL::Digest.new("SHA1")
          end
          fingerprint = fingerprint_alg.hexdigest(cert.to_der)

          # check cert matches registered idp cert
          if fingerprint != idp_cert_fingerprint.gsub(/[^a-zA-Z0-9]/, "").downcase
            return append_error("Fingerprint mismatch", soft)
          end
        else
          return append_error("No cert element", soft)
        end
      else
        if options[:cert]
          base64_cert = Base64.encode(options[:cert].to_pem)
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
        base64_cert = Saml::Utils.element_text(cert_element)
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
        base64_cert = Base64.encode(idp_cert.to_pem)
      end
      validate_signature(base64_cert, true)
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
      sig_alg_value = sig_element.try(&.xpath_node(
        "./ds:SignedInfo/ds:SignatureMethod",
        { "ds" => DSIG }
      ))
      signature_algorithm = algorithm(sig_alg_value)

      # get signature
      signature = if base64_signature = sig_element.try(&.xpath_node("./ds:SignatureValue",{ "ds" => DSIG }))
        if scrubbed_text = Saml::Utils.element_text(base64_signature)
          Base64.decode(scrubbed_text)
        end
      end

      # canonicalization method
      canon_algorithm = canon_algorithm sig_element.try(&.xpath_node(
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

      canon_algorithm = canon_algorithm ref.try(&.xpath_node(
        "//ds:CanonicalizationMethod",
        { "ds" => DSIG }
      ))

      canon_algorithm = process_transforms(ref, canon_algorithm)

      canon_hashed_element = hashed_element.try(&.canonicalize(mode: canon_algorithm, inclusive_ns: inclusive_namespaces))

      # pick something absolutely impossible (worried nil might match sometimes)
      digest_value = "-1"

      if digest_algorithm = algorithm(ref.try(&.xpath_node("//ds:DigestMethod",{ "ds" => DSIG })))
        if hashed = canon_hashed_element
          digest_algorithm << hashed
          hash = digest_algorithm.final
          encoded_digest_value = ref.try(&.xpath_node("//ds:DigestValue",{ "ds" => DSIG }))
          if encoded_text = Saml::Utils.element_text(encoded_digest_value)
            digest_value = Base64.decode(encoded_text)
          end
        end
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
  end
end
