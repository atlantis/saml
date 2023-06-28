require "./spec_helper"

require "onelogin/ruby-saml/logging"

class LoggingTest < Minitest::Test
  describe "Logging" do
    before do
      Saml::Logging.logger = nil
    end

    after do
      Saml::Logging.logger = ::TEST_LOGGER
    end

    describe "given no specific logging setup" do
      it "prints to stdout" do
        Saml::Logging::DEFAULT_LOGGER.expects(:debug).with("hi mom")
        Saml::Logging.debug("hi mom")
      end
    end

    describe "given a Rails app" do
      let(:logger) { mock("Logger") }

      before do
        ::Rails = mock("Rails module")
        ::Rails.stubs(:logger).returns(logger)
      end

      after do
        Object.instance_eval { remove_const(:Rails) }
      end

      it "delegates to Rails" do
        logger.expects(:debug).with("hi mom")
        logger.expects(:info).with("sup?")

        Saml::Logging.debug("hi mom")
        Saml::Logging.info("sup?")
      end
    end

    describe "given a specific Logger" do
      let(:logger) { mock("Logger") }

      before { Saml::Logging.logger = logger }

      after do
        Saml::Logging.logger = ::TEST_LOGGER
      end

      it "delegates to the object" do
        logger.expects(:debug).with("hi mom")
        logger.expects(:info).with("sup?")

        Saml::Logging.debug("hi mom")
        Saml::Logging.info("sup?")
      end
    end
  end
end
