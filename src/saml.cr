require "xml"
require "openssl"
require "openssl_ext"
require "digest"
require "uuid"
require "base64"
require "uri"
require "log"
require "http/client"
require "crypto/subtle"
require "compress/deflate"

module Saml
  VERSION = "0.2.0"

  Log = ::Log.for("saml")
end

require "./saml/lib_xml"
require "./saml/xml_util"
require "./saml/c14n"
require "./saml/error_handling"
require "./saml/validation_error"
require "./saml/saml_message"
require "./saml/redirect_signature"
require "./saml/*"
