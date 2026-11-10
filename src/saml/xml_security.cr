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
  # A parsed XML document. Forwards the XML::Node API to the parsed tree.
  class BaseDocument
    C14N               = "http://www.w3.org/2001/10/xml-exc-c14n#"
    DSIG               = "http://www.w3.org/2000/09/xmldsig#"
    XML_PARSER_OPTIONS = Saml::XMLUtil::PARSER_OPTIONS

    C14N_ALGORITHMS = {
      "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"              => {XML::C14N::Mode::C14N_1_0, false},
      "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments" => {XML::C14N::Mode::C14N_1_0, true},
      "http://www.w3.org/2006/12/xml-c14n11"                         => {XML::C14N::Mode::C14N_1_1, false},
      "http://www.w3.org/2006/12/xml-c14n11#WithComments"            => {XML::C14N::Mode::C14N_1_1, true},
      "http://www.w3.org/2001/10/xml-exc-c14n#"                      => {XML::C14N::Mode::C14N_EXCLUSIVE_1_0, false},
      "http://www.w3.org/2001/10/xml-exc-c14n#WithComments"          => {XML::C14N::Mode::C14N_EXCLUSIVE_1_0, true},
    }

    SIGNATURE_ALGORITHMS = {
      "http://www.w3.org/2000/09/xmldsig#rsa-sha1"        => "SHA1",
      "http://www.w3.org/2001/04/xmldsig-more#rsa-sha1"   => "SHA1",
      "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" => "SHA256",
      "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384" => "SHA384",
      "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512" => "SHA512",
    }

    DIGEST_ALGORITHMS = {
      "http://www.w3.org/2000/09/xmldsig#sha1"        => "SHA1",
      "http://www.w3.org/2001/04/xmlenc#sha1"         => "SHA1",
      "http://www.w3.org/2001/04/xmlenc#sha384"       => "SHA384",
      "http://www.w3.org/2001/04/xmlenc#sha256"       => "SHA256",
      "http://www.w3.org/2001/04/xmldsig-more#sha256" => "SHA256",
      "http://www.w3.org/2001/04/xmldsig-more#sha384" => "SHA384",
      "http://www.w3.org/2001/04/xmlenc#sha512"       => "SHA512",
      "http://www.w3.org/2001/04/xmldsig-more#sha512" => "SHA512",
    }

    getter xml_document : XML::Node

    forward_missing_to @xml_document

    def initialize(@xml_document : XML::Node)
    end

    # Loads untrusted XML strictly (see Saml::XMLUtil.safe_parse).
    def self.safe_load_xml(document) : XML::Node
      Saml::XMLUtil.safe_parse(document.to_s)
    end

    # Legacy mapping: unknown algorithms fall back to exclusive c14n.
    def self.canon_algorithm(element)
      if algorithm = element
        if algorithm.is_a?(XML::Node)
          algorithm = algorithm["Algorithm"]?
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

    # Legacy mapping from an algorithm URI to a fresh digest; unknown means SHA1.
    def self.algorithm(element : XML::Node | String | Nil) : OpenSSL::Digest
      algorithm = element.is_a?(XML::Node) ? element["Algorithm"]? : element
      bits = algorithm && algorithm =~ /(rsa-)?sha(\d+)$/i ? $2.to_i : nil

      case bits
      when 256 then Digest::SHA256.new
      when 384 then OpenSSL::Digest.new("SHA384")
      when 512 then Digest::SHA512.new
      else          Digest::SHA1.new
      end
    end

    # The digest for a signature or digest method URI, nil when it isn't supported.
    def self.strict_digest(uri : String?, table) : OpenSSL::Digest?
      if uri && (name = table[uri]?)
        OpenSSL::Digest.new(name)
      end
    end

    def pem_to_der(pem : String)
      self.class.pem_to_der(pem)
    end

    def self.pem_to_der(pem : String)
      pem.gsub(/-----BEGIN (.*?)-----/, "").gsub(/-----END (.*?)-----/, "").gsub(/\s/m, "")
    end

    # Serialised without formatting changes.
    def to_s : String
      @xml_document.to_xml(options: XML::SaveOptions::AS_XML)
    end

    def to_s(io : IO) : Nil
      io << to_s
    end

    def to_xml : String
      to_s
    end
  end

  # A document Squadron or the SP builds and may sign.
  class Document < BaseDocument
    RSA_SHA1        = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
    RSA_SHA256      = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
    RSA_SHA384      = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"
    RSA_SHA512      = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
    SHA1            = "http://www.w3.org/2000/09/xmldsig#sha1"
    SHA256          = "http://www.w3.org/2001/04/xmlenc#sha256"
    SHA384          = "http://www.w3.org/2001/04/xmldsig-more#sha384"
    SHA512          = "http://www.w3.org/2001/04/xmlenc#sha512"
    ENVELOPED_SIG   = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
    INC_PREFIX_LIST = "#default samlp saml ds xs xsi md"

    setter uuid : String?

    def initialize(tag_name : String, namespaces = {} of String => String)
      root = String.build do |io|
        io << '<' << tag_name
        namespaces.each do |name, value|
          io << ' ' << name << "=\"" << Saml::XMLUtil.escape_attribute(value.to_s) << '"'
        end
        io << "/>"
      end
      super(XML.parse(root, XML_PARSER_OPTIONS))
    end

    def initialize(document : XML::Node)
      super(document)
    end

    # An existing document to sign, parsed strictly.
    def self.parse(xml : String) : Document
      new(BaseDocument.safe_load_xml(xml))
    end

    def uuid : String?
      @uuid ||= root.try(&.[]?("ID"))
    end

    # Enveloped signature over the root element, placed after the Issuer.
    def sign_document(private_key : OpenSSL::PKey::RSA, certificate : OpenSSL::X509::Certificate | String | Nil,
                      signature_method : String? = RSA_SHA1, digest_method : String? = SHA1)
      signature_method ||= RSA_SHA1
      digest_method ||= SHA1
      root = self.root || raise "Document has no root element"
      raise "Document root has no ID to reference" unless uuid

      inclusive_namespaces = INC_PREFIX_LIST.split(" ")
      canon_doc = Canonicalizer.canonicalize(root, XML::C14N::Mode::C14N_EXCLUSIVE_1_0, inclusive_namespaces)

      signature_element = root.add_element("ds:Signature", {"xmlns:ds" => DSIG})
      signed_info_element = signature_element.add_element("ds:SignedInfo")
      signed_info_element.add_element("ds:CanonicalizationMethod", {"Algorithm" => C14N})
      signed_info_element.add_element("ds:SignatureMethod", {"Algorithm" => signature_method})

      reference_element = signed_info_element.add_element("ds:Reference", {"URI" => "##{uuid}"})
      transforms_element = reference_element.add_element("ds:Transforms")
      transforms_element.add_element("ds:Transform", {"Algorithm" => ENVELOPED_SIG})
      c14element = transforms_element.add_element("ds:Transform", {"Algorithm" => C14N})
      c14element.add_element("ec:InclusiveNamespaces", {"xmlns:ec" => C14N, "PrefixList" => INC_PREFIX_LIST})

      digest_method_element = reference_element.add_element("ds:DigestMethod", {"Algorithm" => digest_method})
      reference_element.add_element("ds:DigestValue").text = compute_digest(canon_doc, BaseDocument.algorithm(digest_method_element))

      canon_string = Canonicalizer.canonicalize(signed_info_element, XML::C14N::Mode::C14N_EXCLUSIVE_1_0)
      signature = compute_signature(private_key, BaseDocument.algorithm(signature_method), canon_string)
      signature_element.add_element("ds:SignatureValue").text = signature

      if certificate
        certificate = OpenSSL::X509::Certificate.new(certificate) if certificate.is_a?(String)
        key_info_element = signature_element.add_element("ds:KeyInfo")
        x509_element = key_info_element.add_element("ds:X509Data")
        x509_cert_element = x509_element.add_element("ds:X509Certificate")
        x509_cert_element.text = pem_to_der(certificate.to_pem)
      end

      issuer = Saml::XMLUtil.element_children(root).find { |node| node.name == "Issuer" }
      if issuer
        issuer.add_next_sibling(signature_element)
      elsif first = Saml::XMLUtil.element_children(root).first?
        first.add_prev_sibling(signature_element) unless first == signature_element
      end

      self
    end

    protected def compute_signature(private_key : OpenSSL::PKey::RSA, signature_algorithm, document)
      Base64.strict_encode(private_key.sign(signature_algorithm, document))
    end

    protected def compute_digest(document, digest_algorithm)
      digest_algorithm << document
      Base64.strict_encode(digest_algorithm.final)
    end
  end

  # One ds:Signature resolved against the document: the element it covers and
  # the exact canonical bytes its digest is computed over.
  class SignedReference
    getter signature : XML::Node
    getter signed_info : XML::Node
    getter element : XML::Node
    getter element_id : String
    getter canonical_xml : String
    getter digest : OpenSSL::Digest
    getter digest_value : Bytes
    getter canonical_signed_info : String
    getter signature_digest : String
    getter signature_value : Bytes

    def initialize(@signature, @signed_info, @element, @element_id, @canonical_xml, @digest, @digest_value,
                   @canonical_signed_info, @signature_digest, @signature_value)
    end

    # The X509Certificate of this signature's own KeyInfo, if any.
    def key_info_certificate_text : String?
      if node = Saml::XMLUtil.only_node(signature, "./ds:KeyInfo/ds:X509Data/ds:X509Certificate", {"ds" => BaseDocument::DSIG})
        Saml::XMLUtil.element_text(node).try(&.gsub(/\s/, ""))
      end
    end

    def digest_matches? : Bool
      computed = digest.dup.update(canonical_xml).final
      Crypto::Subtle.constant_time_compare(computed, digest_value)
    end

    def signature_valid?(certificate : OpenSSL::X509::Certificate) : Bool
      key = certificate.public_key
      key.verify(OpenSSL::Digest.new(signature_digest), signature_value, canonical_signed_info)
    rescue
      false
    end
  end

  # A received document whose signatures get verified.
  class SignedDocument < BaseDocument
    include Saml::ErrorHandling

    NAMESPACES = {"ds" => DSIG, "ec" => C14N}

    setter signed_element_id : String?
    getter load_error : String?

    @references = {} of UInt64 => SignedReference | String
    ASSERTION_NS = {"ds" => DSIG, "saml" => "urn:oasis:names:tc:SAML:2.0:assertion"}

    def initialize(response, errors = [] of String)
      @error_messages = errors
      load_error = nil
      parsed = begin
        BaseDocument.safe_load_xml(response.to_s)
      rescue ex : Saml::XMLLoadError
        load_error = ex.message || "XML load failed"
        XML.parse("<invalid/>", XML_PARSER_OPTIONS)
      end
      @load_error = load_error
      super(parsed)
    end

    def loaded? : Bool
      @load_error.nil?
    end

    # The ID the primary signature references.
    def signed_element_id : String?
      @signed_element_id ||= begin
        if (sig = primary_signature) && (ref = reference_node(sig))
          reference_id(sig, ref)
        end
      end
    end

    # The message signature: the only ds:Signature that is a child of the root,
    # else the only one in a direct Assertion child of the root.
    def primary_signature : XML::Node?
      root = self.root
      return nil unless root

      own = root.xpath_nodes("./ds:Signature", NAMESPACES)
      return own[0] if own.size == 1
      return nil if own.size > 1

      nested = root.xpath_nodes("./saml:Assertion/ds:Signature", ASSERTION_NS)
      nested.size == 1 ? nested[0] : nil
    end

    def format_certificate(cert_text : String?) : String?
      return nil unless cert_text

      begin
        if (decoded = Base64.decode_string(cert_text)) && decoded.starts_with?("-----BEGIN CERTIFICATE-----")
          cert_text = decoded
        end
      rescue
      end

      if cert_text.starts_with?("-----BEGIN CERTIFICATE-----")
        cert_text = cert_text.gsub("-----BEGIN CERTIFICATE-----", "").gsub("-----END CERTIFICATE-----", "")
      end
      cert_text = cert_text.gsub(/\s/m, "")

      "-----BEGIN CERTIFICATE-----\n#{Base64.encode(Base64.decode(cert_text)).strip}\n-----END CERTIFICATE-----"
    rescue
      nil
    end

    def load_cert(cert_text : String?) : OpenSSL::X509::Certificate?
      if formatted = format_certificate(cert_text)
        begin
          return OpenSSL::X509::Certificate.new(formatted)
        rescue OpenSSL::X509::CertificateError
        end
      end

      nil
    end

    # Fingerprint mode: trusts the certificate in the signature's own KeyInfo
    # when its fingerprint matches, else falls back to options[:cert].
    def validate_document(idp_cert_fingerprint, soft = true, options = {} of Symbol => String | OpenSSL::X509::Certificate)
      return append_error(@load_error.not_nil!, soft) unless loaded?
      sig = primary_signature
      return append_error("No Signature node found", soft) unless sig

      ref = resolve_reference(sig, soft)
      return false unless ref.is_a?(SignedReference)

      if base64_cert = ref.key_info_certificate_text
        unless cert = load_cert(base64_cert)
          return append_error("Document Certificate Error", soft)
        end

        fingerprint_alg = if (fingeralg = options[:fingerprint_alg]?) && fingeralg.is_a?(String)
                            BaseDocument.algorithm(fingeralg)
                          else
                            Digest::SHA1.new
                          end
        fingerprint_alg << cert.to_der
        fingerprint = fingerprint_alg.hexfinal

        expected = idp_cert_fingerprint.to_s.gsub(/[^a-zA-Z0-9]/, "").downcase
        unless Crypto::Subtle.constant_time_compare(fingerprint.to_slice, expected.to_slice)
          return append_error("Fingerprint mismatch", soft)
        end
      else
        case raw_cert = options[:cert]?
        when OpenSSL::X509::Certificate
          cert = raw_cert
        when String
          cert = load_cert(raw_cert)
          return append_error("Couldn't load X509 certificate", soft) unless cert
        else
          return false if soft
          return append_error("Certificate element missing in response (ds:X509Certificate) and not cert provided at settings", soft)
        end
      end

      verify_reference(ref, [cert], soft)
    end

    # Certificate mode: only the given certificate is trusted. A certificate in
    # the signature's KeyInfo must be that same certificate.
    def validate_document_with_cert(idp_cert : OpenSSL::X509::Certificate, soft = true)
      return append_error(@load_error.not_nil!, soft) unless loaded?
      sig = primary_signature
      return append_error("No Signature node found", soft) unless sig

      ref = resolve_reference(sig, soft)
      return false unless ref.is_a?(SignedReference)

      if cert_text = ref.key_info_certificate_text
        cert = load_cert(cert_text)
        return append_error("Document Certificate Error", soft) unless cert
        unless cert.to_der == idp_cert.to_der
          return append_error("Certificate of the Signature element does not match provided certificate", soft)
        end
      end

      verify_reference(ref, [idp_cert], true)
    end

    # Verifies the primary signature with a base64 (DER or PEM) certificate.
    def validate_signature(base64_cert, soft = true)
      return append_error(@load_error.not_nil!, soft) unless loaded?
      sig = primary_signature
      return append_error("No Signature node found", soft) unless sig

      ref = resolve_reference(sig, soft)
      return false unless ref.is_a?(SignedReference)

      cert = load_cert(base64_cert.try(&.to_s))
      return append_error("Couldn't load X509 certificate", soft) unless cert

      verify_reference(ref, [cert], soft)
    end

    # Verifies one specific signature against the given certificates only.
    def verify_signature(signature : XML::Node, certificates : Array(OpenSSL::X509::Certificate), soft = true) : SignedReference?
      ref = resolve_reference(signature, soft)
      return nil unless ref.is_a?(SignedReference)
      verify_reference(ref, certificates, soft) ? ref : nil
    end

    def verify_reference(ref : SignedReference, certificates : Array(OpenSSL::X509::Certificate), soft = true) : Bool
      unless ref.digest_matches?
        return append_error("Digest mismatch", soft)
      end

      return append_error("No certificate to verify the signature with", soft) if certificates.empty?

      unless certificates.any? { |cert| ref.signature_valid?(cert) }
        return append_error("Key validation error", soft)
      end

      true
    end

    # Checks the structure of one signature and canonicalizes what it covers.
    # Every lookup is relative to this signature (CVE-2024-45409), and the
    # signed element must be its parent with an ID unique in the document.
    def resolve_reference(sig : XML::Node, soft = true) : SignedReference | Bool
      result = reference_for(sig)
      result.is_a?(String) ? append_error(result, soft) : result
    end

    # Like resolve_reference, but returns the problem instead of recording it.
    def reference_for(sig : XML::Node) : SignedReference | String
      @references[sig.to_unsafe.address] ||= build_reference(sig)
    end

    private def build_reference(sig : XML::Node) : SignedReference | String
      return "No Signature node found" unless sig.element? && sig.name == "Signature" && sig.namespace.try(&.href) == DSIG

      signed_info = Saml::XMLUtil.only_node(sig, "./ds:SignedInfo", NAMESPACES)
      return "No SignedInfo node found" unless signed_info
      return "SignedInfo must be the first element of the Signature" unless Saml::XMLUtil.element_children(sig).first? == signed_info

      canon_node = Saml::XMLUtil.only_node(signed_info, "./ds:CanonicalizationMethod", NAMESPACES)
      return "No CanonicalizationMethod found" unless canon_node
      canon = C14N_ALGORITHMS[canon_node["Algorithm"]?.to_s]?
      return "Unsupported canonicalization method" unless canon

      sig_method = Saml::XMLUtil.only_node(signed_info, "./ds:SignatureMethod", NAMESPACES)
      signature_digest = sig_method.try { |node| SIGNATURE_ALGORITHMS[node["Algorithm"]?.to_s]? }
      return "No Signature Algorithm Method found" unless signature_digest

      sig_value_node = Saml::XMLUtil.only_node(sig, "./ds:SignatureValue", NAMESPACES)
      return "No Signature node found" unless sig_value_node
      signature_value = decode_base64(Saml::XMLUtil.element_text(sig_value_node))
      return "Invalid SignatureValue" unless signature_value && !signature_value.empty?

      refs = signed_info.xpath_nodes("./ds:Reference", NAMESPACES)
      return "No Reference node found" if refs.empty?
      return "Found an unexpected number of Reference elements" if refs.size > 1
      ref = refs[0]

      element = sig.parent
      return "Signature has no parent element" unless element && element.element?

      id = reference_id(sig, ref)
      return "Unsupported Reference URI" unless id
      return "Found an invalid Signed Element" unless element["ID"]? == id
      if ref["URI"]?.to_s.empty? && element != root
        return "Found an invalid Signed Element"
      end
      return "Duplicated ID. SAML Response rejected" unless count_ids(id) == 1

      transforms_nodes = ref.xpath_nodes("./ds:Transforms", NAMESPACES)
      return "Found an unexpected number of Transforms elements" if transforms_nodes.size > 1
      transforms = transforms_nodes.empty? ? [] of XML::Node : transforms_nodes[0].xpath_nodes("./ds:Transform", NAMESPACES).to_a
      return "Found an unexpected number of Transform elements" if transforms.size > 2

      digest_mode = canon[0]
      inclusive = nil
      transforms.each do |transform|
        algorithm = transform["Algorithm"]?.to_s
        next if algorithm == Document::ENVELOPED_SIG
        mode = C14N_ALGORITHMS[algorithm]?
        return "Unsupported transform #{algorithm}" unless mode
        digest_mode = mode[0]
        inclusive = inclusive_namespaces_of(transform)
      end

      digest_method = Saml::XMLUtil.only_node(ref, "./ds:DigestMethod", NAMESPACES)
      return "Couldn't find DigestMethod element" unless digest_method
      digest = BaseDocument.strict_digest(digest_method["Algorithm"]?, DIGEST_ALGORITHMS)
      return "Unsupported digest method" unless digest

      digest_value_node = Saml::XMLUtil.only_node(ref, "./ds:DigestValue", NAMESPACES)
      digest_value = decode_base64(Saml::XMLUtil.element_text(digest_value_node))
      return "Invalid DigestValue" unless digest_value && !digest_value.empty?

      begin
        canonical_xml = Canonicalizer.canonicalize(element, digest_mode, inclusive, with_comments: false, exclude: sig)
        canonical_signed_info = Canonicalizer.canonicalize(signed_info, canon[0], inclusive_namespaces_of(canon_node), with_comments: canon[1])
      rescue ex : CanonicalizationError
        return "Canonicalization failed: #{ex.message}"
      end

      SignedReference.new(sig, signed_info, element, id, canonical_xml, digest, digest_value,
        canonical_signed_info, signature_digest, signature_value)
    end

    private def reference_node(sig : XML::Node) : XML::Node?
      Saml::XMLUtil.only_node(sig, "./ds:SignedInfo/ds:Reference", NAMESPACES)
    end

    # "#id" names the element; an empty or missing URI means the signature's parent.
    private def reference_id(sig : XML::Node, ref : XML::Node) : String?
      uri = ref["URI"]?.to_s
      if uri.empty?
        sig.parent.try(&.[]?("ID"))
      elsif uri.starts_with?('#') && uri.size > 1 && !uri.starts_with?("#xpointer(")
        uri[1..]
      end
    end

    private def count_ids(id : String) : Int32
      xpath_float("count(//*[@ID=$id])", nil, {"id" => id}).to_i
    end

    private def inclusive_namespaces_of(node : XML::Node) : Array(String)?
      if element = Saml::XMLUtil.only_node(node, "./ec:InclusiveNamespaces", NAMESPACES)
        element["PrefixList"]?.to_s.split(' ', remove_empty: true)
      end
    end

    private def decode_base64(text : String?) : Bytes?
      return nil unless text
      Base64.decode(text.gsub(/\s/, ""))
    rescue
      nil
    end

    private def extract_inclusive_namespaces : Array(String)
      ref = (sig = primary_signature) ? reference_node(sig) : nil
      return [] of String unless ref

      ref.xpath_nodes("./ds:Transforms/ds:Transform", NAMESPACES).each do |transform|
        if list = inclusive_namespaces_of(transform)
          return list
        end
      end
      [] of String
    end

    def extract_inclusive_namespaces_for_test
      extract_inclusive_namespaces
    end
  end
end
