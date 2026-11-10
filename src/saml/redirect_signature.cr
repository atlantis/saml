module Saml
  # Signature check for messages received over the HTTP-Redirect binding
  # (the Signature query parameter over SAMLRequest/SAMLResponse, RelayState
  # and SigAlg, as the IdP encoded them).
  module RedirectSignature
    alias OptionValue = String | Bool | Int32 | Int64 | Float32 | Float64 | Time::Span | Settings | Hash(String, String) | Nil

    # nil when the message carries no Signature parameter (or the options
    # don't include the GET parameters), else whether it verifies.
    protected def check_redirect_signature(type : String, settings : Settings, options : Hash(Symbol, OptionValue)) : Bool | String | Nil
      get_params = options[:get_params]?
      return nil unless get_params.is_a?(Hash(String, String))
      signature = get_params["Signature"]?
      return nil unless signature

      raw = options[:raw_get_params]?
      raw_params = Utils.prepare_raw_get_params(raw.is_a?(Hash(String, String)) ? raw : nil, get_params,
        settings.security[:lowercase_url_encoding]? == true)
      options[:raw_get_params] = raw_params

      sig_alg = get_params["SigAlg"]? || raw_params["SigAlg"]?.try { |value| Utils.url_decode(value) }

      certs = settings.idp_signing_certificates
      if certs.empty?
        return options.has_key?(:relax_signature_validation) ? true : false
      end

      query_string = Utils.build_query_from_raw_parts({
        type:            type,
        raw_data:        raw_params[type]?,
        raw_relay_state: raw_params["RelayState"]?,
        raw_sig_alg:     raw_params["SigAlg"]?,
      })

      cert = certs.find do |candidate|
        Utils.verify_signature({cert: candidate, sig_alg: sig_alg, signature: signature, query_string: query_string})
      end
      return false unless cert

      if settings.security[:check_idp_cert_expiration]? == true && Utils.is_cert_expired(cert)
        return "IdP x509 certificate expired"
      end

      true
    end
  end
end
