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
end

require "./saml/saml_message"
require "./saml/c14n"
require "./saml/*"

module Saml
  VERSION = "0.1.0"

  # TODO: Put your code here
end