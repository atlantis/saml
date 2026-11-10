module XML
  module C14N
    VERSION = "0.1.0"

    enum Mode
      C14N_1_0           = 0
      C14N_EXCLUSIVE_1_0 = 1
      C14N_1_1           = 2
    end
  end
end

module XMLSecurity
  class CanonicalizationError < Exception
  end

  # Canonical XML of one subtree, computed in place on its own document so the
  # in-scope namespaces are the real ones (no re-serialising or re-parsing).
  module Canonicalizer
    # :nodoc:
    record VisibleRange, root : LibXML::Node*, exclude : LibXML::Node*

    TYPE_OFFSET   = offsetof(LibXML::NodeCommon, @type)
    PARENT_OFFSET = offsetof(LibXML::NodeCommon, @parent)

    # Canonicalizes *node* and its descendants, leaving out *exclude* and its
    # descendants (the enveloped signature). Raises on any libxml2 failure and
    # on an empty result, which libxml2 can return for broken input.
    def self.canonicalize(node : XML::Node, mode : XML::C14N::Mode, inclusive_namespaces : Array(String)? = nil,
                          with_comments : Bool = false, exclude : XML::Node? = nil) : String
      doc = node.to_unsafe.value.doc
      raise CanonicalizationError.new("Node has no document") if doc.null?

      range = VisibleRange.new(node.to_unsafe, exclude ? exclude.to_unsafe : Pointer(LibXML::Node).null)

      io = IO::Memory.new
      boxed_io = Box.box(io)
      buffer = LibXML.xmlOutputBufferCreateIO(
        ->(ctx : Void*, data : UInt8*, len : LibC::Int) : LibC::Int {
          Box(IO::Memory).unbox(ctx).write(Slice.new(data, len))
          len
        },
        ->(ctx : Void*) : LibC::Int { 0 },
        boxed_io,
        nil
      )
      raise CanonicalizationError.new("Couldn't create output buffer") if buffer.null?

      prefixes = [] of UInt8*
      if mode == XML::C14N::Mode::C14N_EXCLUSIVE_1_0 && (list = inclusive_namespaces)
        list.each { |prefix| prefixes << prefix.to_unsafe }
      end
      prefixes << Pointer(UInt8).null
      prefixes_ptr = prefixes.size > 1 ? prefixes.to_unsafe : Pointer(UInt8*).null

      result = LibSamlXML.xmlC14NExecute(
        doc, ->Canonicalizer.visible?(Void*, LibXML::Node*, LibXML::Node*),
        pointerof(range).as(Void*), mode.value, prefixes_ptr, with_comments ? 1 : 0, buffer
      )
      closed = LibSamlXML.xmlOutputBufferClose(buffer)

      if result < 0 || closed < 0
        raise CanonicalizationError.new("Canonicalization failed")
      end

      output = io.to_s
      raise CanonicalizationError.new("Canonicalization produced an empty document") if output.empty?
      output
    end

    # :nodoc:
    def self.visible?(data : Void*, node : LibXML::Node*, parent : LibXML::Node*) : LibC::Int
      range = data.as(VisibleRange*).value
      target = node_type(node) == XML::Node::Type::NAMESPACE_DECL ? parent : node

      while !target.null?
        return 0 if target == range.exclude
        return 1 if target == range.root
        target = node_parent(target)
      end
      0
    end

    # xmlNs, xmlAttr and xmlNode share the leading fields; read them by offset
    # so a smaller struct is never copied whole.
    private def self.node_type(node : LibXML::Node*) : XML::Node::Type
      (node.as(UInt8*) + TYPE_OFFSET).as(XML::Node::Type*).value
    end

    private def self.node_parent(node : LibXML::Node*) : LibXML::Node*
      (node.as(UInt8*) + PARENT_OFFSET).as(LibXML::Node**).value
    end
  end
end

class XML::Node
  # Canonical form of this node's subtree (or of the whole document).
  def canonicalize(mode : XML::C14N::Mode? = nil, inclusive_ns : Array(String)? = nil, with_comments : Bool = false) : String
    XMLSecurity::Canonicalizer.canonicalize(self, mode || XML::C14N::Mode::C14N_EXCLUSIVE_1_0, inclusive_ns, with_comments)
  end
end
