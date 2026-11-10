module OpenSSL::X509
  class Certificate
    def not_before : Time?
      Saml::X509Time.to_time(LibCrypto.saml_x509_get0_not_before(self))
    end

    def not_after : Time?
      Saml::X509Time.to_time(LibCrypto.saml_x509_get0_not_after(self))
    end
  end
end

module Saml
  module X509Time
    def self.to_time(asn1 : Void*) : Time?
      return nil if asn1.null?
      tm = LibC::Tm.new
      return nil if LibCrypto.saml_asn1_time_to_tm(asn1, pointerof(tm)) != 1
      Time.utc(tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec)
    end
  end
end
