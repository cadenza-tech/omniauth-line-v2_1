# frozen_string_literal: true

require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    class LineV21 < OmniAuth::Strategies::OAuth2
      DEFAULT_SCOPE = 'profile openid email'
      USER_INFO_URL = 'https://api.line.me/oauth2/v2.1/userinfo'
      ID_TOKEN_VERIFY_URL = 'https://api.line.me/oauth2/v2.1/verify'

      option :name, 'line_v2_1'

      option :client_options, {
        site: 'https://access.line.me',
        authorize_url: '/oauth2/v2.1/authorize',
        token_url: 'https://api.line.me/oauth2/v2.1/token'
      }

      option :authorize_options, [:scope, :state, :nonce, :prompt, :bot_prompt]

      option :scope, DEFAULT_SCOPE

      uid { raw_info['sub'] }

      info do
        prune!({
          name: raw_info['name'],
          nickname: raw_info['sub'],
          image: raw_info['picture'],
          email: id_token_info[:decoded]['email']
        })
      end

      extra do
        hash = {}
        hash[:raw_info] = raw_info unless skip_info?
        hash[:id_token] = id_token_info[:raw] if id_token_info[:raw]
        hash[:id_info] = id_token_info[:decoded] if id_token_info[:decoded]
        prune!(hash)
      end

      credentials do
        hash = { token: access_token.token }
        hash[:expires] = access_token.expires?
        hash[:expires_at] = access_token.expires_at if access_token.expires?
        hash[:refresh_token] = access_token.refresh_token if access_token.refresh_token
        hash
      end

      def raw_info
        @raw_info ||= access_token.get(USER_INFO_URL, headers: { 'Authorization' => "Bearer #{access_token.token}" }).parsed
      end

      def callback_url
        options[:redirect_uri] || (full_host + callback_path)
      end

      def authorize_params
        super.tap do |params|
          %w[scope state nonce prompt bot_prompt].each do |v|
            params[v.to_sym] = request.params[v] if request.params[v]
          end
          params[:scope] ||= DEFAULT_SCOPE
          params[:nonce] ||= SecureRandom.hex(24)
          params[:response_type] = 'code'
          session['omniauth.state'] = params[:state] if params[:state]
          session['omniauth.nonce'] = params[:nonce] if params[:nonce]
        end
      end

      private

      def prune!(hash)
        hash.delete_if do |_, value|
          prune!(value) if value.is_a?(Hash)
          value.nil? || (value.respond_to?(:empty?) && value.empty?)
        end
      end

      def id_token_info
        return @id_token_info if defined?(@id_token_info)

        @id_token_info = { raw: nil, decoded: nil }
        return @id_token_info unless access_token.params['id_token']

        @id_token_info[:raw] = access_token.params['id_token']
        @id_token_info[:decoded] = verify_id_token(access_token.params['id_token'])
        @id_token_info
      end

      def verify_id_token(id_token)
        params = {
          id_token: id_token,
          client_id: options.client_id
        }
        params[:nonce] = session.delete('omniauth.nonce') if session['omniauth.nonce']

        response = client.request(
          :post,
          ID_TOKEN_VERIFY_URL,
          headers: {
            'Content-Type' => 'application/x-www-form-urlencoded'
          },
          body: URI.encode_www_form(params)
        ).parsed

        fail!(:id_token_verification_failed, CallbackError.new(:id_token_verification_failed, response['error_description'])) if response['error']

        response
      rescue StandardError => e
        fail!(:id_token_verification_failed, e)
      end
    end
  end
end
