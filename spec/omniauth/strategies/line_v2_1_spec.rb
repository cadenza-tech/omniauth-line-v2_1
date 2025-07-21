# frozen_string_literal: true

RSpec.describe OmniAuth::Strategies::LineV21 do # rubocop:disable RSpec/SpecFilePathFormat
  let(:options) { {} }
  let(:strategy) { described_class.new('app', 'channel_id', 'channel_secret', options) }

  describe 'default options' do
    it 'has correct default values' do
      expect(strategy.options.name).to eq('line_v2_1')
      expect(strategy.options.scope).to eq('profile openid email')
      expect(strategy.options.client_options.site).to eq('https://access.line.me')
      expect(strategy.options.client_options.authorize_url).to eq('/oauth2/v2.1/authorize')
      expect(strategy.options.client_options.token_url).to eq('https://api.line.me/oauth2/v2.1/token')
    end
  end

  describe 'custom options' do
    context 'with custom scope' do
      let(:options) { { scope: 'profile openid' } }

      it 'uses custom scope' do
        expect(strategy.options.scope).to eq('profile openid')
      end
    end
  end

  describe '#uid' do
    let(:raw_info) { { 'sub' => 'U1234567890abcdefghijklmnopqrstuvwxyz' } }

    before { allow(strategy).to receive(:raw_info).and_return(raw_info) }

    it 'returns the sub from raw_info' do
      expect(strategy.uid).to eq('U1234567890abcdefghijklmnopqrstuvwxyz')
    end
  end

  describe '#info' do
    let(:raw_info) do
      {
        'sub' => 'U1234567890abcdefghijklmnopqrstuvwxyz',
        'name' => 'Test User',
        'picture' => 'https://profile.line-scdn.net/avatar.jpg',
        'email' => 'user@example.com'
      }
    end
    let(:id_token_info) { { raw: nil, decoded: { 'email' => 'user@example.com' } } }

    before { allow(strategy).to receive_messages(raw_info: raw_info, id_token_info: id_token_info) }

    it 'returns correct info hash' do
      info = strategy.info
      expect(info).to eq(
        name: 'Test User',
        nickname: 'U1234567890abcdefghijklmnopqrstuvwxyz',
        image: 'https://profile.line-scdn.net/avatar.jpg',
        email: 'user@example.com'
      )
    end

    it 'prunes empty values' do
      allow(strategy).to receive_messages(
        raw_info: {
          'sub' => 'test',
          'name' => nil,
          'email' => ''
        },
        id_token_info: {
          raw: nil,
          decoded: {
            'email' => nil
          }
        }
      )
      info = strategy.info
      expect(info).to have_key(:nickname)
      expect(info).not_to have_key(:name)
      expect(info).not_to have_key(:email)
    end
  end

  describe '#extra' do
    let(:raw_info) do
      {
        'sub' => 'U1234567890abcdefghijklmnopqrstuvwxyz',
        'name' => 'Test User',
        'picture' => 'https://profile.line-scdn.net/avatar.jpg',
        'email' => 'user@example.com'
      }
    end
    let(:id_token_info) do
      {
        raw: 'test_id_token',
        decoded: {
          'iss' => 'https://access.line.me',
          'sub' => 'U1234567890abcdefghijklmnopqrstuvwxyz',
          'aud' => '1234567890',
          'exp' => 1504169092,
          'iat' => 1504263657,
          'auth_time' => 1504263657,
          'nonce' => '0987654asdf',
          'amr' => ['pwd'],
          'name' => 'Test User',
          'picture' => 'https://profile.line-scdn.net/avatar.jpg',
          'email' => 'user@example.com'
        }
      }
    end

    before { allow(strategy).to receive_messages(raw_info: raw_info, id_token_info: id_token_info) }

    it 'returns correct extra hash' do
      extra = strategy.extra
      expect(extra).to eq(
        raw_info: {
          'sub' => 'U1234567890abcdefghijklmnopqrstuvwxyz',
          'name' => 'Test User',
          'picture' => 'https://profile.line-scdn.net/avatar.jpg',
          'email' => 'user@example.com'
        },
        id_token: 'test_id_token',
        id_info: {
          'iss' => 'https://access.line.me',
          'sub' => 'U1234567890abcdefghijklmnopqrstuvwxyz',
          'aud' => '1234567890',
          'exp' => 1504169092,
          'iat' => 1504263657,
          'auth_time' => 1504263657,
          'nonce' => '0987654asdf',
          'amr' => ['pwd'],
          'name' => 'Test User',
          'picture' => 'https://profile.line-scdn.net/avatar.jpg',
          'email' => 'user@example.com'
        }
      )
    end

    it 'prunes empty values' do
      allow(strategy).to receive(:id_token_info).and_return({
        raw: nil,
        decoded: ''
      })
      extra = strategy.extra
      expect(extra).to have_key(:raw_info)
      expect(extra).not_to have_key(:id_token)
      expect(extra).not_to have_key(:id_info)
    end

    context 'when skip_info is true' do
      before { allow(strategy).to receive(:skip_info?).and_return(true) }

      it 'does not include raw_info' do
        extra = strategy.extra
        expect(extra).not_to have_key(:raw_info)
        expect(extra[:id_token]).to eq('test_id_token')
        expect(extra[:id_info]).to eq({
          'iss' => 'https://access.line.me',
          'sub' => 'U1234567890abcdefghijklmnopqrstuvwxyz',
          'aud' => '1234567890',
          'exp' => 1504169092,
          'iat' => 1504263657,
          'auth_time' => 1504263657,
          'nonce' => '0987654asdf',
          'amr' => ['pwd'],
          'name' => 'Test User',
          'picture' => 'https://profile.line-scdn.net/avatar.jpg',
          'email' => 'user@example.com'
        })
      end
    end
  end

  describe '#credentials' do
    let(:access_token) do
      instance_double(
        OAuth2::AccessToken,
        token: 'token',
        expires?: true,
        expires_at: 1234567890,
        refresh_token: 'refresh_token'
      )
    end

    before { allow(strategy).to receive(:access_token).and_return(access_token) }

    it 'returns credentials hash' do
      credentials = strategy.credentials
      expect(credentials).to include(
        token: 'token',
        expires: true,
        expires_at: 1234567890,
        refresh_token: 'refresh_token'
      )
    end

    context 'when access token does not expire' do
      let(:access_token) do
        instance_double(
          OAuth2::AccessToken,
          token: 'token',
          expires?: false,
          refresh_token: 'refresh_token'
        )
      end

      it 'does not include expires_at' do
        credentials = strategy.credentials
        expect(credentials).to include(
          token: 'token',
          expires: false,
          refresh_token: 'refresh_token'
        )
        expect(credentials).not_to have_key(:expires_at)
      end
    end

    context 'without refresh token' do
      let(:access_token) do
        instance_double(
          OAuth2::AccessToken,
          token: 'token',
          expires?: true,
          expires_at: 1234567890,
          refresh_token: nil
        )
      end

      it 'does not include refresh_token' do
        credentials = strategy.credentials
        expect(credentials).to include(
          token: 'token',
          expires: true,
          expires_at: 1234567890
        )
        expect(credentials).not_to have_key(:refresh_token)
      end
    end
  end

  describe '#raw_info' do
    let(:access_token) { instance_double(OAuth2::AccessToken, token: 'token') }
    let(:response) { instance_double(OAuth2::Response, parsed: { 'sub' => 'U1234567890abcdefghijklmnopqrstuvwxyz' }) }

    before do
      allow(access_token).to receive(:get).and_return(response)
      allow(strategy).to receive(:access_token).and_return(access_token)
    end

    it 'fetches user info from API' do
      expect(strategy.raw_info).to eq({ 'sub' => 'U1234567890abcdefghijklmnopqrstuvwxyz' })
    end

    it 'memoizes the result' do
      2.times { strategy.raw_info }
      expect(access_token).to have_received(:get).once
    end
  end

  describe '#callback_url' do
    context 'without redirect_uri option' do
      it 'builds callback url from request' do
        allow(strategy).to receive_messages(full_host: 'https://example.com', callback_path: '/auth/line_v2_1/callback')
        expect(strategy.callback_url).to eq('https://example.com/auth/line_v2_1/callback')
      end
    end

    context 'with redirect_uri option' do
      let(:options) { { redirect_uri: 'https://custom.example.com/callback' } }

      it 'uses redirect_uri option' do
        expect(strategy.callback_url).to eq('https://custom.example.com/callback')
      end
    end
  end

  describe '#authorize_params' do
    let(:request) { instance_double(Rack::Request, params: {}) }

    before { allow(strategy).to receive_messages(request: request, session: {}) }

    it 'includes default scope when not specified' do
      params = strategy.authorize_params
      expect(params[:scope]).to eq('profile openid email')
    end

    it 'includes response_type as code' do
      params = strategy.authorize_params
      expect(params[:response_type]).to eq('code')
    end

    context 'with scope in request params' do
      let(:request) { instance_double(Rack::Request, params: { 'scope' => 'profile openid' }) }

      it 'uses scope from request params' do
        params = strategy.authorize_params
        expect(params[:scope]).to eq('profile openid')
      end
    end

    context 'with state in request params' do
      let(:request) { instance_double(Rack::Request, params: { 'state' => '12345abcde' }) }

      it 'includes state in params and stores in session' do
        params = strategy.authorize_params
        expect(params[:state]).to eq('12345abcde')
        expect(strategy.session['omniauth.state']).to eq('12345abcde')
      end
    end

    context 'with nonce in request params' do
      let(:request) { instance_double(Rack::Request, params: { 'nonce' => '0987654asdf' }) }

      it 'includes nonce in params and stores in session' do
        params = strategy.authorize_params
        expect(params[:nonce]).to eq('0987654asdf')
        expect(strategy.session['omniauth.nonce']).to eq('0987654asdf')
      end
    end

    context 'with prompt in request params' do
      let(:request) { instance_double(Rack::Request, params: { 'prompt' => 'consent' }) }

      it 'includes prompt in params and stores in session' do
        params = strategy.authorize_params
        expect(params[:prompt]).to eq('consent')
      end
    end

    context 'with bot_prompt in request params' do
      let(:request) { instance_double(Rack::Request, params: { 'bot_prompt' => 'aggressive' }) }

      it 'includes bot_prompt in params and stores in session' do
        params = strategy.authorize_params
        expect(params[:bot_prompt]).to eq('aggressive')
      end
    end
  end

  describe '#prune!' do
    it 'removes nil values from hash' do
      hash = { a: 1, b: nil, c: 'test' }
      expect(strategy.send(:prune!, hash)).to eq({ a: 1, c: 'test' })
    end

    it 'removes empty string values from hash' do
      hash = { a: 'value', b: '', c: 'another' }
      expect(strategy.send(:prune!, hash)).to eq({ a: 'value', c: 'another' })
    end

    it 'removes empty array values from hash' do
      hash = { a: [1, 2], b: [], c: ['test'] }
      expect(strategy.send(:prune!, hash)).to eq({ a: [1, 2], c: ['test'] })
    end

    it 'removes empty hash values from hash' do
      hash = { a: { x: 1 }, b: {}, c: { y: 2 } }
      expect(strategy.send(:prune!, hash)).to eq({ a: { x: 1 }, c: { y: 2 } })
    end

    it 'keeps zero values' do
      hash = { a: 0, b: nil, c: 'value' }
      expect(strategy.send(:prune!, hash)).to eq({ a: 0, c: 'value' })
    end

    it 'keeps false values' do
      hash = { a: false, b: nil, c: true }
      expect(strategy.send(:prune!, hash)).to eq({ a: false, c: true })
    end

    it 'handles nested hashes' do
      hash = { a: { x: 1, y: nil, z: '' }, b: { w: nil, x: '', y: [], z: {} }, c: { nested: { value: 'test', empty: nil } } }
      result = strategy.send(:prune!, hash)
      expect(result).to eq({ a: { x: 1 }, c: { nested: { value: 'test' } } })
    end

    it 'modifies the original hash' do
      hash = { a: 1, b: nil, c: 'test' }
      result = strategy.send(:prune!, hash)
      expect(hash.object_id).to eq(result.object_id)
      expect(hash).to eq({ a: 1, c: 'test' })
    end
  end

  describe '#id_token_info' do
    let(:client) { instance_double(OAuth2::Client) }
    let(:response) do
      instance_double(
        OAuth2::Response,
        parsed: {
          'iss' => 'https://access.line.me',
          'sub' => 'U1234567890',
          'aud' => 'channel_id',
          'exp' => 1234567890,
          'iat' => 1234567890,
          'nonce' => '0987654asdf',
          'name' => 'Test User',
          'picture' => 'https://profile.line-scdn.net/avatar.jpg'
        }
      )
    end
    let(:access_token) { instance_double(OAuth2::AccessToken, params: { 'id_token' => 'test_id_token' }) }

    before do
      allow(client).to receive(:request).and_return(response)
      allow(strategy).to receive_messages(access_token: access_token, session: { 'omniauth.nonce' => '0987654asdf' }, client: client)
    end

    it 'returns id token info with raw and decoded data' do
      id_token_info = strategy.send(:id_token_info)
      expect(id_token_info[:raw]).to eq('test_id_token')
      expect(id_token_info[:decoded]).to eq({
        'iss' => 'https://access.line.me',
        'sub' => 'U1234567890',
        'aud' => 'channel_id',
        'exp' => 1234567890,
        'iat' => 1234567890,
        'nonce' => '0987654asdf',
        'name' => 'Test User',
        'picture' => 'https://profile.line-scdn.net/avatar.jpg'
      })
    end

    context 'when id_token is not present' do
      let(:access_token) { instance_double(OAuth2::AccessToken, params: {}) }

      it 'returns empty id token info' do
        id_token_info = strategy.send(:id_token_info)
        expect(id_token_info).to eq({ raw: nil, decoded: nil })
      end
    end

    context 'when verification fails' do
      let(:response) { instance_double(OAuth2::Response, parsed: nil) }

      before { allow(strategy).to receive(:log) }

      it 'returns nil for decoded data' do
        id_token_info = strategy.send(:id_token_info)
        expect(id_token_info[:raw]).to eq('test_id_token')
        expect(id_token_info[:decoded]).to be_nil
      end
    end
  end

  describe '#verify_id_token' do
    let(:client) { instance_double(OAuth2::Client) }
    let(:response) do
      instance_double(
        OAuth2::Response,
        parsed: {
          'iss' => 'https://access.line.me',
          'sub' => 'U1234567890',
          'aud' => 'channel_id',
          'exp' => 1234567890,
          'iat' => 1234567890,
          'name' => 'Test User',
          'picture' => 'https://profile.line-scdn.net/avatar.jpg'
        }
      )
    end

    before do
      allow(client).to receive(:request).and_return(response)
      options_mock = OmniAuth::Strategy::Options.new(client_id: 'channel_id')
      allow(strategy).to receive_messages(client: client, session: {}, options: options_mock)
    end

    it 'sends verification request to LINE API' do
      strategy.send(:verify_id_token, 'test_id_token')
      expect(client).to have_received(:request).with(
        :post,
        'https://api.line.me/oauth2/v2.1/verify',
        headers: {
          'Content-Type' => 'application/x-www-form-urlencoded'
        },
        body: 'id_token=test_id_token&client_id=channel_id'
      )
    end

    it 'includes nonce when present in session' do
      allow(strategy).to receive(:session).and_return({ 'omniauth.nonce' => '0987654asdf' })
      strategy.send(:verify_id_token, 'test_id_token')
      expect(client).to have_received(:request).with(
        :post,
        'https://api.line.me/oauth2/v2.1/verify',
        headers: {
          'Content-Type' => 'application/x-www-form-urlencoded'
        },
        body: 'id_token=test_id_token&client_id=channel_id&nonce=0987654asdf'
      )
    end

    it 'returns parsed response on success' do
      result = strategy.send(:verify_id_token, 'test_id_token')
      expect(result).to eq({
        'iss' => 'https://access.line.me',
        'sub' => 'U1234567890',
        'aud' => 'channel_id',
        'exp' => 1234567890,
        'iat' => 1234567890,
        'name' => 'Test User',
        'picture' => 'https://profile.line-scdn.net/avatar.jpg'
      })
    end

    context 'when verification fails' do
      before do
        allow(client).to receive(:request).and_raise(StandardError, 'Verification failed')
        allow(strategy).to receive(:log)
      end

      it 'logs error and returns nil' do
        result = strategy.send(:verify_id_token, 'test_id_token')
        expect(result).to be_nil
        expect(strategy).to have_received(:log).with(:error, 'ID token verification failed: Verification failed')
      end
    end
  end
end
