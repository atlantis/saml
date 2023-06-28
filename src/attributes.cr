module Saml

  # SAML2 Attributes. Parse the Attributes from the AttributeStatement of the SAML Response.
  #
  class Attributes
    alias AttributeValue = String | Int32 | Bool
    include Enumerable(AttributeValue)

    getter :attributes

    # @param attrs [Hash] The +attrs+ must be a Hash with attribute names as keys and **arrays** as values:
    #    Attributes.new({
    #      'name' => ['value1', 'value2'],
    #      'mail' => ['value1'],
    #    })
    #
    def initialize(attrs : Hash(String, Array(AttributeValue)))
      @attributes = attrs
    end

    # Iterate over all attributes
    #
    def each
      attributes.each { |name, values| yield name, values }
    end

    # Test attribute presence by name
    # @param name [String] The attribute name to be checked
    #
    def includes?(name)
      attributes.has_key?(canonize_name(name))
    end

    # Return first value for an attribute
    # @param name [String] The attribute name
    # @return [String] The value (First occurrence)
    #
    def single(name)
      attributes[canonize_name(name)].first if includes?(name)
    end

    # Return all values for an attribute
    # @param name [String] The attribute name
    # @return [Array] Values of the attribute
    #
    def multi(name)
      attributes[canonize_name(name)]
    end

    # Retrieve attribute value(s)
    # @param name [String] The attribute name
    # @return [String|Array] Depending on the single value compatibility status this returns:
    #                        - First value if single_value_compatibility = true
    #                          response.attributes['mail']  # => 'user@example.com'
    #                        - All values if single_value_compatibility = false
    #                          response.attributes['mail']  # => ['user@example.com','user@example.net']
    #
    def [](name)
      multi(canonize_name(name))
    end

    # @return [Hash] Return all attributes as a hash
    #
    def all
      attributes
    end

    # @param name [String] The attribute name
    # @param values [Array] The values
    #
    def set(name, values)
      attributes[canonize_name(name)] = values
    end

    alias_method :[]=, :set

    # @param name [String] The attribute name
    # @param values [Array] The values
    #
    def add(name : String, values = [] of AttributeValue)
      attributes[canonize_name(name)] ||= [] of AttributeValue
      attributes[canonize_name(name)] += values
    end

    # Make comparable to another Attributes collection based on attributes
    # @param other [Attributes] An Attributes object to compare with
    # @return [Boolean] True if are contains the same attributes and values
    #
    def ==(other)
      if other.is_a?(Attributes)
        all == other.all
      else
        super
      end
    end

    # Fetch attribute value using name or regex
    # @param name [String|Regexp] The attribute name
    # @return [String|Array] Depending on the single value compatibility status this returns:
    #                        - First value if single_value_compatibility = true
    #                          response.attributes['mail']  # => 'user@example.com'
    #                        - All values if single_value_compatibility = false
    #                          response.attributes['mail']  # => ['user@example.com','user@example.net']
    #
    def fetch(name)
      attributes.each_key do |attribute_key|
        if name.is_a?(Regexp)
          if name.responds_to? :match?
            return self[attribute_key] if name.match?(attribute_key)
          else
            return self[attribute_key] if name.match(attribute_key)
          end
        elsif canonize_name(name) == canonize_name(attribute_key)
          return self[attribute_key]
        end
      end
      nil
    end

    def each(&) : AttributeValue
      attributes.each do |attribute|
        yield attribute
      end
    end

    # stringifies all names so both 'email' and :email return the same result
    # @param name [String] The attribute name
    # @return [String] stringified name
    #
    protected def canonize_name(name)
      name.to_s
    end
  end
end
