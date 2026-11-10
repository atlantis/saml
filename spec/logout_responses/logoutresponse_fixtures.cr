# Logout response documents for the Logoutresponse and SloLogoutrequest specs.
# Include it in a describe; it supplies `settings` unless the describe defines its own.
module LogoutresponseFixtures
  DEFAULT_LOGOUT_RESPONSE_UUID = "_28024690-000e-0130-b6d2-38f6b112be8b"

  @settings : Saml::Settings?

  def valid_logout_response_document(opts = {} of Symbol => String) : String
    logout_response_document("urn:oasis:names:tc:SAML:2.0:status:Success", nil, opts)
  end

  def unsuccessful_logout_response_document(opts = {} of Symbol => String) : String
    logout_response_document("urn:oasis:names:tc:SAML:2.0:status:Requester", nil, opts)
  end

  def unsuccessful_logout_response_with_message_document(opts = {} of Symbol => String) : String
    logout_response_document("urn:oasis:names:tc:SAML:2.0:status:Requester", "Logoutrequest expired", opts)
  end

  def invalid_xml_logout_response_document : String
    "<samlp:SomethingAwful
        xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"
        ID=\"#{random_id}\" Version=\"2.0\">
      </samlp:SomethingAwful>"
  end

  def settings : Saml::Settings
    @settings ||= Saml::Settings.new({
      :assertion_consumer_service_url => "http://app.muda.no/sso/consume",
      :single_logout_service_url      => "http://app.muda.no/sso/consume_logout",
      :issuer                         => "http://app.muda.no",
      :sp_name_qualifier              => "http://sso.muda.no",
      :idp_sso_service_url            => "http://sso.muda.no/sso",
      :idp_slo_service_url            => "http://sso.muda.no/slo",
      :idp_cert_fingerprint           => "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00",
      :name_identifier_format         => "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
    })
  end

  private def logout_response_document(status_code : String, status_message : String?, opts) : String
    uuid = opts[:uuid]? || DEFAULT_LOGOUT_RESPONSE_UUID
    issue_instant = opts[:issue_instant]? || Time.utc.to_s("%Y-%m-%dT%H:%M:%SZ")
    message = status_message ? "\n      <samlp:StatusMessage>#{status_message}</samlp:StatusMessage>" : ""

    "<samlp:LogoutResponse
        xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"
        ID=\"#{random_id}\" Version=\"2.0\"
        IssueInstant=\"#{issue_instant}\"
        Destination=\"#{settings.single_logout_service_url}\"
        InResponseTo=\"#{uuid}\">
      <saml:Issuer xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">#{settings.issuer}</saml:Issuer>
      <samlp:Status xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\">
      <samlp:StatusCode xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"
          Value=\"#{status_code}\">
      </samlp:StatusCode>#{message}
      </samlp:Status>
      </samlp:LogoutResponse>"
  end
end
