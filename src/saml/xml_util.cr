module Saml
  # Raised when a message can't be loaded as XML (malformed, DOCTYPE, too large).
  class XMLLoadError < Exception
  end

  # XML helpers shared by every SAML message.
  module XMLUtil
    # No RECOVER: libxml2 must refuse anything that isn't well-formed rather than repair it.
    PARSER_OPTIONS = XML::ParserOptions::NONET

    # Parses untrusted XML: well-formed only, no DOCTYPE, no network, and no
    # errors or warnings at all (namespace errors don't stop libxml2 by themselves).
    def self.safe_parse(xml : String) : XML::Node
      raise XMLLoadError.new("Document is empty") if xml.strip.empty?
      if xml.includes?("<!DOCTYPE") || xml.includes?("<!ENTITY")
        raise XMLLoadError.new("Dangerous XML detected. No Doctype nodes allowed")
      end

      begin
        doc = XML.parse(xml, PARSER_OPTIONS)
      rescue ex : XML::Error
        raise XMLLoadError.new("XML load failed: #{ex.message}")
      end

      unless doc.to_unsafe.as(LibXML::Doc*).value.int_subset.null?
        raise XMLLoadError.new("Dangerous XML detected. No Doctype nodes allowed")
      end

      if (errors = document_errors(doc)) && !errors.empty?
        raise XMLLoadError.new("There were XML errors when parsing: #{errors.map(&.message).join("; ")}")
      end

      raise XMLLoadError.new("Document has no root element") unless doc.root

      doc
    end

    private def self.document_errors(doc)
      {% if compare_versions(Crystal::VERSION, "1.13.0") >= 0 %}
        doc.as(XML::Document).errors
      {% else %}
        doc.errors
      {% end %}
    end

    # Concatenates the element's own text and CDATA children only, so comments
    # and child elements can't change or truncate the value.
    def self.element_text(element : XML::Node?) : String?
      return nil unless element

      String.build do |io|
        element.children.each do |child|
          io << child.content if child.text? || child.cdata?
        end
      end
    end

    def self.escape_attribute(value : String) : String
      value.gsub({'&' => "&amp;", '<' => "&lt;", '>' => "&gt;", '"' => "&quot;"})
    end

    # Element children only, in document order.
    def self.element_children(node : XML::Node) : Array(XML::Node)
      node.children.select(&.element?)
    end

    # Exactly one match or nil.
    def self.only_node(node, path : String, namespaces = nil, variables = nil) : XML::Node?
      nodes = node.xpath_nodes(path, namespaces, variables)
      nodes.size == 1 ? nodes[0] : nil
    end

    # Adds an element under *parent* in the same document. Names and attributes
    # may be prefixed; "xmlns"/"xmlns:p" entries declare namespaces.
    def self.add_element(parent : XML::Node, name : String, attributes = nil) : XML::Node
      doc = parent.to_unsafe.value.doc
      prefix, local = split_name(name)
      ptr = LibSamlXML.xmlNewDocNode(doc, Pointer(LibXML::NS).null, local, Pointer(UInt8).null)
      raise "Couldn't create node #{name}" if ptr.null?
      LibSamlXML.xmlAddChild(parent.to_unsafe, ptr)

      if attrs = attributes
        attrs.each do |key, value|
          next if value.nil?
          key = key.to_s
          if key == "xmlns"
            LibSamlXML.xmlNewNs(ptr, value.to_s, Pointer(UInt8).null)
          elsif key.starts_with?("xmlns:")
            LibSamlXML.xmlNewNs(ptr, value.to_s, key[6..])
          end
        end
      end

      ns = LibSamlXML.xmlSearchNs(doc, ptr, prefix ? prefix.to_unsafe : Pointer(UInt8).null)
      if prefix && ns.null?
        raise "Namespace prefix #{prefix} is not declared for #{name}"
      end
      LibSamlXML.xmlSetNs(ptr, ns) unless ns.null?

      if attrs = attributes
        attrs.each do |key, value|
          next if value.nil?
          key = key.to_s
          next if key == "xmlns" || key.starts_with?("xmlns:")
          set_attribute(ptr, key, value.to_s)
        end
      end

      wrap(parent, ptr)
    end

    def self.set_attribute(node : XML::Node, name : String, value : String) : Nil
      set_attribute(node.to_unsafe, name, value)
    end

    private def self.set_attribute(ptr : LibXML::Node*, name : String, value : String) : Nil
      prefix, local = split_name(name)
      if prefix
        ns = LibSamlXML.xmlSearchNs(ptr.value.doc, ptr, prefix)
        raise "Namespace prefix #{prefix} is not declared for attribute #{name}" if ns.null?
        LibSamlXML.xmlSetNsProp(ptr, ns, local, value)
      else
        LibXML.xmlSetProp(ptr, local, value)
      end
    end

    # Moves *node* (already in the same document) right after *sibling*.
    def self.add_next_sibling(sibling : XML::Node, node : XML::Node) : XML::Node
      LibSamlXML.xmlAddNextSibling(sibling.to_unsafe, node.to_unsafe)
      node
    end

    # Moves *node* (already in the same document) right before *sibling*.
    def self.add_prev_sibling(sibling : XML::Node, node : XML::Node) : XML::Node
      LibSamlXML.xmlAddPrevSibling(sibling.to_unsafe, node.to_unsafe)
      node
    end

    # Moves *node* (already in the same document) to the end of *parent*.
    def self.add_child(parent : XML::Node, node : XML::Node) : XML::Node
      LibSamlXML.xmlAddChild(parent.to_unsafe, node.to_unsafe)
      node
    end

    private def self.split_name(name : String) : {String?, String}
      if idx = name.index(':')
        {name[0, idx], name[idx + 1..]}
      else
        {nil, name}
      end
    end

    # Finds the wrapper for a libxml node through the public API, so it stays
    # tied to its document.
    private def self.wrap(parent : XML::Node, ptr : LibXML::Node*) : XML::Node
      parent.children.each do |child|
        return child if child.to_unsafe == ptr
      end
      raise "Created node not found"
    end
  end
end

class XML::Node
  def add_element(tag_name : String, attributes = nil) : XML::Node
    Saml::XMLUtil.add_element(self, tag_name, attributes)
  end

  def add_child(node : XML::Node) : XML::Node
    Saml::XMLUtil.add_child(self, node)
  end

  def <<(node : XML::Node)
    add_child(node)
  end

  def add_next_sibling(node : XML::Node) : XML::Node
    Saml::XMLUtil.add_next_sibling(self, node)
  end

  def add_prev_sibling(node : XML::Node) : XML::Node
    Saml::XMLUtil.add_prev_sibling(self, node)
  end
end
