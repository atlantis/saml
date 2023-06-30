require "xml"
require "openssl"
require "openssl_ext"
require "digest"
require "uuid"
require "compress/zlib"

class XML::Node
  # Removes the node from the XML document.
  def add_child( node : Node ) : Nil
    LibXML.xmlXPathNodeSetAddUnique(self.children.to_unsafe, node.to_unsafe)
  end

  def <<( node : Node )
    self.add_child( node )
  end

  def add_element(tag_name, namespaces  = {} of String => String)
    namespaces_string = namespaces.map { |k,v| "#{k}=\"#{v}\"" }.join(" ")
    if node = XML.parse("<#{tag_name}#{ " #{namespaces_string}" if namespaces_string}></#{tag_name}>", )
      self << node
      node
    else
      raise "Couldn't create node #{tag_name}"
    end
  end
end

class XML::NodeSet
  def <<( node : Node )
    LibXML.xmlXPathNodeSetAddUnique(self.to_unsafe, node.to_unsafe)
  end
end

lib LibCrypto
  fun asn1_time_print =  ASN1_TIME_print(b : Bio, s : ASN1_TIME)
  fun x509_get_notbefore = X509_get0_notBefore(x509 : X509) : ASN1_TIME
  fun x509_get_notafter = X509_get0_notAfter(x509 : X509) : ASN1_TIME
end

module OpenSSL::X509
  class Certificate
    def not_before : Time?
      if timestamp  = LibCrypto.x509_get_notbefore(self)
        buffer = LibCrypto::Bio.new
        LibCrypto.asn1_time_print( buffer.to_unsafe, timestamp )
        puts "TIME not_before: #{buffer.to_s}"
        Time.parse_utc(buffer.to_s, "MMM DD HH:MM:SS YYYY")
      end

    end

    def not_after : Time?
      if timestamp = LibCrypto.x509_get_notafter(self)
        buffer = LibCrypto::Bio.new
        LibCrypto.asn1_time_print( buffer, timestamp )
        puts "TIME not_after: #{buffer.to_s}"
        Time.parse_utc(buffer.to_s, "MMM DD HH:MM:SS YYYY")
      end
    end
  end
end

require "./saml/saml_message"
require "./saml/c14n"
require "./saml/*"

module Saml
  VERSION = "0.1.0"

  # TODO: Put your code here
end