module XML
  module C14N
    VERSION = "0.0.1"

    enum Mode
      C14N_1_0           = 0
      C14N_EXCLUSIVE_1_0 = 1
      C14N_1_1           = 2
    end
  end
end

class XML::Node
  include XML::C14N

  def canonicalize(io = IO::Memory.new)
    canonicalize(io, Mode::C14N_EXCLUSIVE_1_0, false)
  end

  def canonicalize(io, mode, comments?)
    canonicalize(io, mode, nil, nil, comments?)
  end

  def canonicalize(io = IO::Memory.new, mode : Mode? = nil, node_set = nil, inclusive_ns : Array(String) = [] of String, comments? = false)
    mode ||= Mode::C14N_EXCLUSIVE_1_0
    output_buffer = canonical_out_buffer(io)
    comments = comments? ? 1 : 0
    LibC14N.xmlC14NDocSaveTo(self, node_set, mode, inclusive_ns.map(&.to_unsafe), comments, output_buffer)
    LibC14N.xmlOutputBufferClose(output_buffer)
    return io.to_s if io.class == IO::Memory
    io
  end

  def canonicalize!
    canon = self.canonicalize.as String
    node = LibXML.xmlDocGetRootElement(LibXML.xmlReadMemory(canon, canon.bytesize, nil, nil, ParserOptions.default))
    self.initialize(node)
  end

  private def canonical_out_buffer(io)
    ctx = io
    LibXML.xmlOutputBufferCreateIO(
      ->(ctx, buffer, len) {
        Box(IO).unbox(ctx).write Slice.new(buffer, len)
        len
      },
      ->(ctx) { 0 },
      Box(IO).box(ctx),
      nil
    )
  end
end

@[Link("xml2")]
lib LibC14N
  alias OutputWriteCallback = (Void*, UInt8*, Int32) -> Int32
  alias OutputCloseCallback = (Void*) -> Int32

  type CharEncodingHandler = Void*
  type OutputBuffer = Void*

  fun xmlOutputBufferClose(out : LibXML::OutputBuffer*) : Int32
  fun xmlC14NDocSaveTo(doc : LibXML::Node*, nodes : LibXML::NodeSet*, mode : XML::C14N::Mode, inclusive_ns_prefixes : UInt8**, with_comments : Int32, buf : LibXML::OutputBuffer*) : Int32
end

