module Doorkeeper
  module OAuth
    module RequestConcern
      def authorize
        validate
        if valid?
          before_successful_response
          @response = TokenResponse.new(access_token)
          after_successful_response
          @response
        else
          @response = ErrorResponse.from_request(self)
        end
      end

      def scopes
        @scopes ||= if @original_scopes.present?
                      OAuth::Scopes.from_string(@original_scopes)
                    else
                      default_scopes
                    end
      end

      def default_scopes
        server.default_scopes
      end

      def valid?
        error.nil?
      end

      def access_token_expiration(server, client)
        if client && client.custom_expiration_time
          client.custom_expiration_time
        else
          server.access_token_expires_in
        end
      end

      def find_or_create_access_token(client, resource_owner_id, scopes, server)
        @access_token = AccessToken.find_or_create_for(
          client,
          resource_owner_id,
          scopes,
          access_token_expiration(server, client),
          server.refresh_token_enabled?)
      end

      def before_successful_response
      end

      def after_successful_response
      end
    end
  end
end
