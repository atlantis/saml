module Saml
  module ErrorHandling
    @error_messages = [] of String

    # Appends the error and, unless soft, raises it as a ValidationError.
    # *soft_override* replaces the object's own soft setting for this call.
    def append_error(error_msg : String, soft_override : Bool? = nil) : Bool
      @error_messages << error_msg

      soft = if soft_override.nil?
               responds_to?(:soft) ? (self.soft != false) : true
             else
               soft_override
             end
      raise ValidationError.new(error_msg) unless soft

      false
    end

    # Clears in place: documents share this array.
    def reset_errors!
      @error_messages.clear
    end

    def errors : Array(String)
      @error_messages
    end
  end
end
