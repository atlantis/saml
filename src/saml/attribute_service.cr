module Saml
  # SAML2 AttributeService. Auxiliary class to build the AttributeService of the SP Metadata
  #
  class AttributeService
    alias AttributeOption = String | Int32 | Bool | Array(String | Int32 | Bool) | Nil

    getter attributes = [] of Hash(Symbol, AttributeOption)
    getter name : String?
    getter index : String = "1"

    # Evaluates the block with this service as its receiver.
    def configure(&)
      with self yield
    end

    # @return [Boolean] True if the AttributeService has attributes and a name
    def configured? : Bool
      !attributes.empty? && !name.nil?
    end

    # Set a name to the service
    def service_name(name)
      @name = name.to_s
    end

    # Set an index to the service
    def service_index(index)
      @index = index.to_s
    end

    # Add a requested attribute:
    #   add_attribute({:name => "Name", :name_format => "Name Format", :friendly_name => "Friendly Name",
    #                  :is_required => true, :attribute_value => "Attribute Value"})
    def add_attribute(options : Hash)
      attribute = {} of Symbol => AttributeOption
      options.each do |key, value|
        attribute[key] = value.is_a?(Array) ? value.map { |v| v.as(String | Int32 | Bool) } : value
      end
      attributes << attribute
    end
  end
end
