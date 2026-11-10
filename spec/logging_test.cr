require "./spec_helper"

describe "Logging" do
  let(:settings) do
    Saml::Settings.new({:idp_sso_service_url => "http://example.com/sso"})
  end

  # log/spec's Log.capture pulls in the stdlib spec DSL, which clashes with minitest's describe.
  def capture_saml_log(level : ::Log::Severity, &)
    backend = ::Log::MemoryBackend.new
    ::Log.builder.bind("saml", level, backend)
    begin
      yield
    ensure
      ::Log.builder.unbind("saml", level, backend)
    end
    backend.entries
  end

  it "logs the created AuthnRequest at debug level" do
    entries = capture_saml_log(::Log::Severity::Debug) do
      Saml::Authrequest.new.create(settings)
    end
    entry = entries.find { |e| e.message.starts_with?("Created AuthnRequest: ") }
    refute_nil(entry)
    entry = entry.not_nil!
    assert_equal(::Log::Severity::Debug, entry.severity)
    assert_equal("saml", entry.source)
    assert_includes(entry.message, "<samlp:AuthnRequest")
  end

  it "logs nothing above debug level" do
    entries = capture_saml_log(::Log::Severity::Info) do
      Saml::Authrequest.new.create(settings)
    end
    assert_empty(entries)
  end
end
