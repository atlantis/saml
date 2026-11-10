# libxml2 functions the stdlib XML binding doesn't declare.
@[Link("xml2")]
lib LibSamlXML
  alias Node = LibXML::Node
  alias Doc = LibXML::Doc
  alias NS = LibXML::NS

  alias IsVisibleCallback = (Void*, Node*, Node*) -> LibC::Int
  alias StructuredErrorFunc = (Void*, LibXML::Error*) ->

  fun xmlC14NExecute(doc : Doc*, is_visible : IsVisibleCallback, user_data : Void*, mode : LibC::Int,
                     inclusive_ns_prefixes : UInt8**, with_comments : LibC::Int, buf : LibXML::OutputBuffer*) : LibC::Int
  fun xmlOutputBufferClose(out : LibXML::OutputBuffer*) : LibC::Int

  fun xmlNewDocNode(doc : Doc*, ns : NS*, name : UInt8*, content : UInt8*) : Node*
  fun xmlNewNs(node : Node*, href : UInt8*, prefix : UInt8*) : NS*
  fun xmlSearchNs(doc : Doc*, node : Node*, prefix : UInt8*) : NS*
  fun xmlSetNs(node : Node*, ns : NS*) : Void
  fun xmlSetNsProp(node : Node*, ns : NS*, name : UInt8*, value : UInt8*) : Void*
  fun xmlAddChild(parent : Node*, cur : Node*) : Node*
  fun xmlAddNextSibling(cur : Node*, elem : Node*) : Node*
  fun xmlAddPrevSibling(cur : Node*, elem : Node*) : Node*
  fun xmlReconciliateNs(doc : Doc*, tree : Node*) : LibC::Int
  fun xmlDocCopyNode(node : Node*, doc : Doc*, recursive : LibC::Int) : Node*

  fun xmlSchemaNewParserCtxt(url : UInt8*) : Void*
  fun xmlSchemaSetParserStructuredErrors(ctxt : Void*, serror : StructuredErrorFunc, ctx : Void*) : Void
  fun xmlSchemaParse(ctxt : Void*) : Void*
  fun xmlSchemaFreeParserCtxt(ctxt : Void*) : Void
  fun xmlSchemaNewValidCtxt(schema : Void*) : Void*
  fun xmlSchemaSetValidStructuredErrors(ctxt : Void*, serror : StructuredErrorFunc, ctx : Void*) : Void
  fun xmlSchemaValidateDoc(ctxt : Void*, doc : Doc*) : LibC::Int
  fun xmlSchemaFreeValidCtxt(ctxt : Void*) : Void
end

lib LibCrypto
  fun saml_x509_get0_not_before = X509_get0_notBefore(x509 : X509) : Void*
  fun saml_x509_get0_not_after = X509_get0_notAfter(x509 : X509) : Void*
  fun saml_asn1_time_to_tm = ASN1_TIME_to_tm(s : Void*, tm : LibC::Tm*) : LibC::Int
end

lib LibCrypto
  fun saml_evp_get_cipherbyname = EVP_get_cipherbyname(name : UInt8*) : Void*
  fun saml_evp_cipher_ctx_new = EVP_CIPHER_CTX_new : Void*
  fun saml_evp_cipher_ctx_free = EVP_CIPHER_CTX_free(ctx : Void*) : Void
  fun saml_evp_decrypt_init_ex = EVP_DecryptInit_ex(ctx : Void*, cipher : Void*, engine : Void*, key : UInt8*, iv : UInt8*) : LibC::Int
  fun saml_evp_decrypt_update = EVP_DecryptUpdate(ctx : Void*, out : UInt8*, outl : LibC::Int*, input : UInt8*, inl : LibC::Int) : LibC::Int
  fun saml_evp_decrypt_final_ex = EVP_DecryptFinal_ex(ctx : Void*, out : UInt8*, outl : LibC::Int*) : LibC::Int
  fun saml_evp_cipher_ctx_ctrl = EVP_CIPHER_CTX_ctrl(ctx : Void*, type : LibC::Int, arg : LibC::Int, ptr : Void*) : LibC::Int
end
