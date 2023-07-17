require "./spec_helper"

# expose private methods for tests
module Saml
  class Response
    def send(method : Symbol, option : XML::Node? = nil)
      case method
      when :decrypt_assertion
        self.decrypt_assertion(option.not_nil!)
      when :xpath_first_from_signed_assertion
        self.xpath_first_from_signed_assertion
      when :validate_signed_elements
        self.validate_signed_elements
      when :validate_structure
        self.validate_structure
      when :validate_audience
        self.validate_audience
      when :validate_destination
        self.validate_destination
      when :validate_issuer
        self.validate_issuer
      when :validate_num_assertion
        self.validate_num_assertion
      when :validate_success_status
        self.validate_success_status
      when :validate_in_response_to
        self.validate_in_response_to
      when :validate_subject_confirmation
        self.validate_subject_confirmation
      when :validate_session_expiration
        self.validate_session_expiration
      when :validate_signature
        self.validate_signature
      when :validate_name_id
        self.validate_name_id
      when :validate_one_authnstatement
        self.validate_one_authnstatement
      when :validate_conditions
        self.validate_conditions
      when :validate_no_duplicated_attributes
        self.validate_no_duplicated_attributes
      when :validate_one_conditions
        self.validate_one_conditions
      else
        raise "Missing .send hack for method #{method}"
      end
    end
  end

  class SpecialResponse1 < Saml::Response
    def initialize(response, options = {} of Symbol => OptionValue)
      super(response, options)
      @document = XMLSecurity::SpecialSignedDocument1.new(@response, @error_messages)

      if assertion_encrypted?
        @decrypted_document = generate_decrypted_document
      end
    end

    def validate_conditions
      true
    end
  end

  class SpecialResponse2 < Saml::Response
    def conditions
      nil
    end
  end

  class SpecialResponse3 < Saml::Response
    def conditions
      nil
    end

    def validate_subject_confirmation
      true
    end
  end

  class SpecialResponse4 < Saml::Response
    def conditions
      nil
    end
  end

  class SpecialResponse5 < Saml::Response
    def conditions
      nil
    end

    def validate_subject_confirmation
      true
    end

    def validate_signature
      true
    end
  end

  class SpecialSignedDocument1 < XMLSecurity::SignedDocument
    def digests_match?
      true
    end
  end
end

class RubySamlTest < Minitest::Test
  describe "Response" do
    describe "retrieve nameID and attributes from encrypted assertion" do
      it "parses populi response" do
        settings = Saml::Settings.new
        settings.assertion_consumer_service_url = "https://james.ngrok.io/services/648cf50cd8e846b4f27998c2/saml/receive"
        settings.idp_cert_fingerprint = "0E:18:1E:A3:27:5D:4D:8D:92:EC:C9:4E:7B:45:1B:D8:61:09:D6:18"
        raw = "PHNhbWxwOlJlc3BvbnNlIHhtbG5zOnNhbWxwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiIHhtbG5zOnNhbWw9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iIElEPSJfZjIwZjViNThiMzBkNTc4ODNmM2E5M2ExZDcxOTEyZTE5YTAyZjUxNjMwIiBWZXJzaW9uPSIyLjAiIElzc3VlSW5zdGFudD0iMjAyMy0wNy0xNFQyMTowMjoxN1oiIERlc3RpbmF0aW9uPSJodHRwczovL2phbWVzLm5ncm9rLmlvL3NlcnZpY2VzLzY0OGNmNTBjZDhlODQ2YjRmMjc5OThjMi9zYW1sL3JlY2VpdmUiIEluUmVzcG9uc2VUbz0iX2IwODM5MWYzLWIxMWMtNDMxMy1iOTI3LTJkMGQxMTAxNDNiOSI+PHNhbWw6SXNzdWVyPnBvcHVsaS5jbzwvc2FtbDpJc3N1ZXI+PGRzOlNpZ25hdHVyZSB4bWxuczpkcz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnIyI+CiAgPGRzOlNpZ25lZEluZm8+PGRzOkNhbm9uaWNhbGl6YXRpb25NZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz4KICAgIDxkczpTaWduYXR1cmVNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjcnNhLXNoYTEiLz4KICA8ZHM6UmVmZXJlbmNlIFVSST0iI19mMjBmNWI1OGIzMGQ1Nzg4M2YzYTkzYTFkNzE5MTJlMTlhMDJmNTE2MzAiPjxkczpUcmFuc2Zvcm1zPjxkczpUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjZW52ZWxvcGVkLXNpZ25hdHVyZSIvPjxkczpUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz48L2RzOlRyYW5zZm9ybXM+PGRzOkRpZ2VzdE1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNzaGExIi8+PGRzOkRpZ2VzdFZhbHVlPlUwQkhreFFKWXNudjZtRXhsYmpEbHkvUEU2RT08L2RzOkRpZ2VzdFZhbHVlPjwvZHM6UmVmZXJlbmNlPjwvZHM6U2lnbmVkSW5mbz48ZHM6U2lnbmF0dXJlVmFsdWU+VEJNQU9DSGh3RHFaVUFncThISmNhdkdVbStiUm9BakpvVFRwVUpKSm5MbzZMOVVyR2dKWnJaVy85ZWRydVZOU1JONE8yU1BLRFVtdHJNRmNCVGRCTEs0YXFJNlJkdkRjUTJVOXozVjFqd2kza0JwVDQwSksxcE81MDAvK3pkZk1RVFk1ckd4c2dvNTZpbjE3S0lkaUh4OWlTdkhRMitHV0wrNlo2aFo1OW9RSGJNc3NhZnZrMHgrcFd2aktYcE1LSUV5M0lLMnZjNER1dGhoVUtxTnJvVjNJZFBnTFpUSFErbGMxZ3dmR2VNbThuUy9VWm9KOVgyUkhSWk5ybmJtSlJEVDV6bXhpMUovbTZ6dlZjMC9sVkcvRkw1Q0R1em1QNUEwTmVjd0JuZ1lnbktRY2szYjNyajVFZzZFYWVZUjlnUE1mU1ZXVzlnbHBkK0ZvTXZIbFh3PT08L2RzOlNpZ25hdHVyZVZhbHVlPgo8ZHM6S2V5SW5mbz48ZHM6WDUwOURhdGE+PGRzOlg1MDlDZXJ0aWZpY2F0ZT5NSUlFUlRDQ0F5MmdBd0lCQWdJSkFLall5Q1U5L1pic01BMEdDU3FHU0liM0RRRUJCUVVBTUhReEN6QUpCZ05WQkFZVEFsVlRNUXN3Q1FZRFZRUUlFd0pKUkRFUE1BMEdBMVVFQnhNR1RXOXpZMjkzTVJNd0VRWURWUVFLRXdwUWIzQjFiR2tnU1c1ak1SSXdFQVlEVlFRREV3bHdiM0IxYkdrdVkyOHhIakFjQmdrcWhraUc5dzBCQ1FFV0QycGhiV1Z6UUhCdmNIVnNhUzVqYnpBZUZ3MHhOREF4TVRVeE9ESTRNREZhRncweU5EQXhNVFV4T0RJNE1ERmFNSFF4Q3pBSkJnTlZCQVlUQWxWVE1Rc3dDUVlEVlFRSUV3SkpSREVQTUEwR0ExVUVCeE1HVFc5elkyOTNNUk13RVFZRFZRUUtFd3BRYjNCMWJHa2dTVzVqTVJJd0VBWURWUVFERXdsd2IzQjFiR2t1WTI4eEhqQWNCZ2txaGtpRzl3MEJDUUVXRDJwaGJXVnpRSEJ2Y0hWc2FTNWpiekNDQVNJd0RRWUpLb1pJaHZjTkFRRUJCUUFEZ2dFUEFEQ0NBUW9DZ2dFQkFONXViRFB1RjZwNS84MUNLRXhTN05heWhNTzl4c1ZXZkZSOHpHQUtWYXlEaGdQN0R3UVVNK2ZzOE14SUpGWGEyWnUzWVlpV2J3dVZZYWExRFZOT01KNEpyL3d5MkR0eFlPNXE4M0xtWkRDMjZMZ2FxdGhCaDk2RVRUeTRCbzF2Qm5YdWZqSlo3Ym1ZaWRIYjg3ZnU4OStjOFNyQ0pIU2hhUFVrV2kycXJqY3gxeWJocEt5MUdVd0x0RTgvdDVTSXRjLy9La2xHc0dpNnFlMExzd1JNOHBmU3crNm1vUjR0WnhHemNuN2N4Q3kvcEJGdjhYc3EvNHd0Q0E3aDIrRUQzMzZFcGZPdHhHN3RPY0MyR2ZLa3lramszSnpQZTlJZkMrMk8zb2oyNWR2MDdsVTlrUVNmTGM2R1lZZ1lRRXhITjNhMlJKNnVRWUh1b2ljVlIzdThpd2NDQXdFQUFhT0IyVENCMWpBZEJnTlZIUTRFRmdRVWloazAyNDNnU2lmbHhXNUFKVjNPN0h4TVN2VXdnYVlHQTFVZEl3U0JuakNCbTRBVWloazAyNDNnU2lmbHhXNUFKVjNPN0h4TVN2V2hlS1IyTUhReEN6QUpCZ05WQkFZVEFsVlRNUXN3Q1FZRFZRUUlFd0pKUkRFUE1BMEdBMVVFQnhNR1RXOXpZMjkzTVJNd0VRWURWUVFLRXdwUWIzQjFiR2tnU1c1ak1SSXdFQVlEVlFRREV3bHdiM0IxYkdrdVkyOHhIakFjQmdrcWhraUc5dzBCQ1FFV0QycGhiV1Z6UUhCdmNIVnNhUzVqYjRJSkFLall5Q1U5L1pic01Bd0dBMVVkRXdRRk1BTUJBZjh3RFFZSktvWklodmNOQVFFRkJRQURnZ0VCQURSZHd2Z2hYYkJhN0w3d2FSZjBNTzVDVm5iYU5nc1J0cmVTeEN3azlKeHRKUUdSSjU1QUJFYXd0WCt2cENVaE5lZTZRZ0luTVNZNk1Dc3pNVHNwSjFOKzM4OElobzFlQlJ4RW55SlE3VmZ6d1g0Myt3SjRselRVeXQySlhGZzFVUkxIS1F5azc4Rm84ZlFjdTJ5YU85dW1WeDhRcnNyRjVxbVZKR2VDQjAzeUZaMitSaGNQVTFZdUE1WlpVZUdqVFAvdzQ5aHUvYzZCR1ZsTTNEcTJTNGlDV3M2SHpwakF1Q0srVisrN0tzSXNOOVo1TGtOd1JPM1J6dml0czNIcjM3TVMzR01ESk5CNVA5dzRoRGx0bjc3N2RJc3pjM1B1UUVpZVZrWlhXUmZ0cVhUWFMvOWlYQWpBS1BURjIwVXU2L3QxalhkSGtUTXhDVGhaL0w3OGRrST08L2RzOlg1MDlDZXJ0aWZpY2F0ZT48L2RzOlg1MDlEYXRhPjwvZHM6S2V5SW5mbz48L2RzOlNpZ25hdHVyZT48c2FtbHA6U3RhdHVzPjxzYW1scDpTdGF0dXNDb2RlIFZhbHVlPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6c3RhdHVzOlN1Y2Nlc3MiLz48L3NhbWxwOlN0YXR1cz48c2FtbDpBc3NlcnRpb24geG1sbnM6eHNpPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYS1pbnN0YW5jZSIgeG1sbnM6eHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hIiBJRD0iXzUwOTc5YTYxZGJjMTk1NTMwNWVkMzMxZWU3YTY2YTM4MDNiNTg3ODAzNyIgVmVyc2lvbj0iMi4wIiBJc3N1ZUluc3RhbnQ9IjIwMjMtMDctMTRUMjE6MDI6MTdaIj48c2FtbDpJc3N1ZXI+cG9wdWxpLmNvPC9zYW1sOklzc3Vlcj48c2FtbDpTdWJqZWN0PjxzYW1sOk5hbWVJRCBGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjEuMTpuYW1laWQtZm9ybWF0OmVtYWlsQWRkcmVzcyI+amFtZXNAbnNhLmVkdTwvc2FtbDpOYW1lSUQ+PHNhbWw6U3ViamVjdENvbmZpcm1hdGlvbiBNZXRob2Q9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpjbTpiZWFyZXIiPjxzYW1sOlN1YmplY3RDb25maXJtYXRpb25EYXRhIE5vdE9uT3JBZnRlcj0iMjAyMy0wNy0xNFQyMTowNzoxN1oiIFJlY2lwaWVudD0iaHR0cHM6Ly9qYW1lcy5uZ3Jvay5pby9zZXJ2aWNlcy82NDhjZjUwY2Q4ZTg0NmI0ZjI3OTk4YzIvc2FtbC9yZWNlaXZlIiBJblJlc3BvbnNlVG89Il9iMDgzOTFmMy1iMTFjLTQzMTMtYjkyNy0yZDBkMTEwMTQzYjkiLz48L3NhbWw6U3ViamVjdENvbmZpcm1hdGlvbj48L3NhbWw6U3ViamVjdD48c2FtbDpDb25kaXRpb25zIE5vdEJlZm9yZT0iMjAyMy0wNy0xNFQyMTowMTo0N1oiIE5vdE9uT3JBZnRlcj0iMjAyMy0wNy0xNFQyMTowNzoxN1oiPjxzYW1sOkF1ZGllbmNlUmVzdHJpY3Rpb24+PHNhbWw6QXVkaWVuY2U+bnNhLndhdGNobWFyay5jbG91ZDwvc2FtbDpBdWRpZW5jZT48L3NhbWw6QXVkaWVuY2VSZXN0cmljdGlvbj48L3NhbWw6Q29uZGl0aW9ucz48c2FtbDpBdXRoblN0YXRlbWVudCBBdXRobkluc3RhbnQ9IjIwMjMtMDctMTRUMjE6MDI6MTdaIiBTZXNzaW9uSW5kZXg9Il9mMzJlOWFkYmI2MzQ3YzMzMTczZjIwZDcxZDM2ZWZlOGE0NTg5OWY5NTYiPjxzYW1sOkF1dGhuQ29udGV4dD48c2FtbDpBdXRobkNvbnRleHRDbGFzc1JlZj51cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YWM6Y2xhc3NlczpQYXNzd29yZDwvc2FtbDpBdXRobkNvbnRleHRDbGFzc1JlZj48L3NhbWw6QXV0aG5Db250ZXh0Pjwvc2FtbDpBdXRoblN0YXRlbWVudD48c2FtbDpBdHRyaWJ1dGVTdGF0ZW1lbnQ+PHNhbWw6QXR0cmlidXRlIE5hbWU9IkZpcnN0TmFtZSI+PHNhbWw6QXR0cmlidXRlVmFsdWUgeHNpOnR5cGU9InhzOnN0cmluZyI+SmFtZXM8L3NhbWw6QXR0cmlidXRlVmFsdWU+PC9zYW1sOkF0dHJpYnV0ZT48c2FtbDpBdHRyaWJ1dGUgTmFtZT0iTGFzdE5hbWUiPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhzaTp0eXBlPSJ4czpzdHJpbmciPkhpbGw8L3NhbWw6QXR0cmlidXRlVmFsdWU+PC9zYW1sOkF0dHJpYnV0ZT48c2FtbDpBdHRyaWJ1dGUgTmFtZT0iRW1haWwiPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhzaTp0eXBlPSJ4czpzdHJpbmciPmphbWVzQG5zYS5lZHU8L3NhbWw6QXR0cmlidXRlVmFsdWU+PC9zYW1sOkF0dHJpYnV0ZT48c2FtbDpBdHRyaWJ1dGUgTmFtZT0idXJuOm9pZDowLjkuMjM0Mi4xOTIwMDMwMC4xMDAuMS4zIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4c2k6dHlwZT0ieHM6c3RyaW5nIj5qYW1lc0Buc2EuZWR1PC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PHNhbWw6QXR0cmlidXRlIE5hbWU9InVybjpvaWQ6MC45LjIzNDIuMTkyMDAzMDAuMTAwLjEiPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhzaTp0eXBlPSJ4czpzdHJpbmciPmphbWVzPC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PHNhbWw6QXR0cmlidXRlIE5hbWU9IlBvcHVsaUlEIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4c2k6dHlwZT0ieHM6aW50ZWdlciI+ODQ2NTwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRlPjwvc2FtbDpBdHRyaWJ1dGVTdGF0ZW1lbnQ+PC9zYW1sOkFzc2VydGlvbj48L3NhbWxwOlJlc3BvbnNlPg=="
        response = Saml::Response.new(Base64.decode_string(raw), {:settings => settings})

        Timecop.travel(Time.parse_rfc3339("2023-07-14 21:07:17Z")) do
          response.is_valid?
          puts "ERRORS: #{response.errors.inspect}"
          assert response.is_valid?
        end
      end
    end
  end
end