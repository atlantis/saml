require "xml"
require "openssl"
require "openssl_ext"
require "digest"
require "uuid"
require "compress/zlib"

class XML::Node
  # Adds the node to the XML document.
  def add_child( node : Node ) : Nil
    #LibXML.xmlXPathNodeSetAddUnique(self.children.to_unsafe, node.to_unsafe)
    LibXML.xmlAddChild(self, node.to_unsafe)
  end

  def <<( node : Node )
    self.add_child( node )
  end

  def add_element(tag_name, namespaces  = {} of String => String)
    namespaces_string = namespaces.map { |k,v| "#{k}=\"#{v}\"" }.join(" ")
    # have to do it this way so it knows the new node is a fragment
    if wrapper_node = XML.parse("<root><#{tag_name}#{ " #{namespaces_string}" if namespaces_string}></#{tag_name}></root>")
      node = wrapper_node.xpath_node("/root/*").not_nil!
      self << node
      node
    else
      raise "Couldn't create node #{tag_name}"
    end
  end

  def add_next_sibling(node : Node)
    if result = LibXML.xmlAddNextSibling(self.to_unsafe, node.to_unsafe)
      if (root = self.root) && (parent = self.parent)
        LibXML.xmlReconciliateNs(root.to_unsafe, parent.to_unsafe)
      end

      Node.new(result)
    end
  end

  def add_prev_sibling(node : Node)
    if result = LibXML.xmlAddPrevSibling(self.to_unsafe, node.to_unsafe)
      if (root = self.root)&& (parent = self.parent)
        LibXML.xmlReconciliateNs(root.to_unsafe, parent.to_unsafe)
      end
      Node.new(result)
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

lib LibXML
  fun xmlAddChild(parent : Node*, cur : Node*) : Node*
  fun xmlAddNextSibling(cur : Node*, element : Node*) : Node*
  fun xmlAddPrevSibling(cur : Node*, element : Node*) : Node*
  fun xmlReconciliateNs(doc : Node*, tree : Node*) : Int32
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

#Have to override this to ignore the header and checksum
class SamlZlibReader < Compress::Zlib::Reader
  def self.open(io : IO, sync_close = false, dict : Bytes? = nil, &)
    reader = SamlZlibReader.new(io, sync_close: sync_close, dict: dict)
    yield reader ensure reader.close
  end

  # Creates a new reader from the given *io*.
  def initialize(@io : IO, @sync_close = false, dict : Bytes? = nil)
    @flate_io = Compress::Deflate::Reader.new(@io, dict: dict)
    @adler32 = ::Digest::Adler32.initial
    @end = false
  end

  def unbuffered_read(slice : Bytes) : Int32
    check_open

    return 0 if slice.empty?
    return 0 if @end

    read_bytes = @flate_io.read(slice)
    if read_bytes == 0
      # Check ADLER-32
      @end = true
      @flate_io.close
    end
    read_bytes
  end

end

require "./saml/saml_message"
require "./saml/c14n"
require "./saml/*"

module Saml
  VERSION = "0.1.0"

  # TODO: Put your code here
end