module Saml
  module ErrorHandling
    property errors_messages = [] of String

    # Append the cause to the errors array, and based on the value of soft, return false or raise
    # an exception. soft_override is provided as a means of overriding the object's notion of
    # soft for just this invocation.
    def append_error(error_msg : String, soft_override : Bool? = nil)
      @error_messages << error_msg

      soft = self.responds_to?(:soft) ? self.soft : true
      unless soft_override.nil? ? soft : soft_override
        raise ValidationError.new(error_msg)
      end

      false
    end

    # Reset the errors array
    def reset_errors!
      @error_messages = [] of String
    end

    def errors
      @error_messages
    end
  end
end
