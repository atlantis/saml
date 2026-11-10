module Saml
  # SAML2 Attributes. Parse the Attributes from the AttributeStatement of the SAML Response.
  #
  class Attributes
    alias AttributeValue = String?

    include Enumerable({String, Array(AttributeValue)})

    getter attributes : Hash(String, Array(AttributeValue))

    # @param attrs [Hash] attribute names to arrays of values
    def initialize(attrs : Hash(String, Array(AttributeValue)) = {} of String => Array(AttributeValue))
      @attributes = attrs
    end

    def each(& : {String, Array(AttributeValue)} ->)
      attributes.each { |name, values| yield({name, values}) }
    end

    # Test attribute presence by name
    def includes?(name) : Bool
      attributes.has_key?(canonize_name(name))
    end

    # Return first value for an attribute
    def single(name) : AttributeValue
      attributes[canonize_name(name)]?.try(&.first?)
    end

    # Return all values for an attribute
    def multi(name) : Array(AttributeValue)?
      attributes[canonize_name(name)]?
    end

    # All values of the attribute, nil when it is missing.
    def [](name) : Array(AttributeValue)?
      multi(name)
    end

    # @return [Hash] Return all attributes as a hash
    def all : Hash(String, Array(AttributeValue))
      attributes
    end

    # Name to non-nil values, as plain strings.
    def to_h : Hash(String, Array(String))
      attributes.transform_values(&.compact)
    end

    def set(name, values : Array(AttributeValue))
      attributes[canonize_name(name)] = values
    end

    def []=(name, values : Array(AttributeValue))
      set(name, values)
    end

    def add(name, values : Array(AttributeValue) = [] of AttributeValue)
      key = canonize_name(name)
      attributes[key] = (attributes[key]? || [] of AttributeValue) + values
    end

    def ==(other : Attributes)
      all == other.all
    end

    # Fetch attribute value using name or regex
    def fetch(name : String | Symbol | Regex) : Array(AttributeValue)?
      attributes.each_key do |attribute_key|
        if name.is_a?(Regex)
          return self[attribute_key] if name.matches?(attribute_key)
        elsif canonize_name(name) == canonize_name(attribute_key)
          return self[attribute_key]
        end
      end
      nil
    end

    protected def canonize_name(name) : String
      name.to_s
    end
  end
end
