# frozen_string_literal: true
# Original idea from https://github.com/google/google-id-token
require "json"
require "jwt"
require "monitor"
require "net/http"
require "openssl"
require "firebase_id_token"

module FirebaseIDToken
  class CertificateError < StandardError; end
  class ValidationError < StandardError; end
  class ExpiredTokenError < ValidationError; end
  class SignatureError < ValidationError; end
  class InvalidIssuerError < ValidationError; end
  class AudienceMismatchError < ValidationError; end
  class ClientIDMismatchError < ValidationError; end

  # Verify the correct token
  # https://firebase.google.com/docs/auth/admin/verify-id-tokens#retrieve_id_tokens_on_clients
  class Validator
    include MonitorMixin

    def initialize(project_id:, redis_url:)
      ::FirebaseIdToken.configure do |config|
        config.project_ids = [project_id]
        config.redis = Redis.new(url: redis_url)
      end
      super()
    end

    # @param [String] token
    #   The string form of the token
    #
    # @return [Hash] The decoded ID token
    def check(token)
      payload = begin
                  ::FirebaseIdToken::Signature.verify(token)
                rescue ::FirebaseIdToken::Exceptions::NoCertificatesError
                  ::FirebaseIdToken::Certificates.request!
                  check(token)
                end

      raise SignatureError, "Token not verified as issued by Google" unless payload
      payload
    end
  end
end
