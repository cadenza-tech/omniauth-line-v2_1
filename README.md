# OmniauthLineV2.1

[![License](https://img.shields.io/github/license/cadenza-tech/omniauth-line-v2_1?label=License&labelColor=343B42&color=blue)](https://github.com/cadenza-tech/omniauth-line-v2_1/blob/main/LICENSE.txt) [![Tag](https://img.shields.io/github/tag/cadenza-tech/omniauth-line-v2_1?label=Tag&logo=github&labelColor=343B42&color=2EBC4F)](https://github.com/cadenza-tech/omniauth-line-v2_1/blob/main/CHANGELOG.md) [![Release](https://github.com/cadenza-tech/omniauth-line-v2_1/actions/workflows/release.yml/badge.svg)](https://github.com/cadenza-tech/omniauth-line-v2_1/actions?query=workflow%3Arelease) [![Test](https://github.com/cadenza-tech/omniauth-line-v2_1/actions/workflows/test.yml/badge.svg)](https://github.com/cadenza-tech/omniauth-line-v2_1/actions?query=workflow%3Atest) [![Lint](https://github.com/cadenza-tech/omniauth-line-v2_1/actions/workflows/lint.yml/badge.svg)](https://github.com/cadenza-tech/omniauth-line-v2_1/actions?query=workflow%3Alint)

LINE strategy for OmniAuth.

- [Installation](#installation)
- [Usage](#usage)
  - [Rails Configuration with Devise](#rails-configuration-with-devise)
  - [Configuration Options](#configuration-options)
  - [Auth Hash](#auth-hash)
- [Changelog](#changelog)
- [Contributing](#contributing)
- [License](#license)
- [Code of Conduct](#code-of-conduct)
- [Sponsor](#sponsor)

## Installation

Install the gem and add to the application's Gemfile by executing:

```bash
bundle add omniauth-line-v2_1
```

If bundler is not being used to manage dependencies, install the gem by executing:

```bash
gem install omniauth-line-v2_1
```

## Usage

### Rails Configuration with Devise

Add the following to `config/initializers/devise.rb`:

```ruby
# config/initializers/devise.rb
Devise.setup do |config|
  config.omniauth :line_v2_1, ENV['LINE_CHANNEL_ID'], ENV['LINE_CHANNEL_SECRET']
end
```

Add the OmniAuth callbacks routes to `config/routes.rb`:

```ruby
# config/routes.rb
Rails.application.routes.draw do
  devise_for :users, controllers: { omniauth_callbacks: 'users/omniauth_callbacks' }
end
```

Add the OmniAuth configuration to your Devise model:

```ruby
class User < ApplicationRecord
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :validatable,
         :omniauthable, omniauth_providers: [:line_v2_1]
end
```

### Configuration Options

You can configure several options:

```ruby
# config/initializers/devise.rb
Devise.setup do |config|
  config.omniauth :line_v2_1, ENV['LINE_CHANNEL_ID'], ENV['LINE_CHANNEL_SECRET'],
    {
      scope: 'profile openid', # Specify OAuth scopes
      callback_path: '/custom/line_v2_1/callback', # Custom callback path
      prompt: 'consent', # Optional: force consent screen
      bot_prompt: 'aggressive' # Optional: LINE official account linking
    }
end
```

Available scopes:

- `profile` - Access to user's display name and profile image
- `openid` - Required for ID token (includes user identifier)
- `email` - Access to user's email address

### Auth Hash

After successful authentication, the auth hash will be available in `request.env['omniauth.auth']`:

```ruby
{
  provider: 'line_v2_1',
  uid: 'U4af4980629...',
  info: {
    name: 'Taro Line',
    nickname: 'U4af4980629...',
    image: 'https://profile.line-scdn.net/...',
    email: 'taro.line@example.com'
  },
  credentials: {
    token: 'bNl4YEFPI/hjFWhTqexp4MuEw5YPs...',
    expires: true,
    expires_at: 1504169092,
    refresh_token: 'Aa1FdeggRhTnPNNpxr8p'
  },
  extra: {
    raw_info: {
      sub: 'U4af4980629...',
      name: 'Taro Line',
      picture: 'https://profile.line-scdn.net/...'
    },
    id_token: 'eyJhbGciOiJIUzI1NiJ9...',
    id_info: {
      iss: 'https://access.line.me',
      sub: 'U4af4980629...',
      aud: '1234567890',
      exp: 1504169092,
      iat: 1504263657,
      auth_time: 1504263657,
      nonce: '0987654asdf',
      amr: ['pwd'],
      name: 'Taro Line',
      picture: 'https://profile.line-scdn.net/...',
      email: 'taro.line@example.com'
    }
  }
}
```

## Changelog

See [CHANGELOG.md](https://github.com/cadenza-tech/omniauth-line-v2_1/blob/main/CHANGELOG.md).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/cadenza-tech/omniauth-line-v2_1. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [code of conduct](https://github.com/cadenza-tech/omniauth-line-v2_1/blob/main/CODE_OF_CONDUCT.md).

## License

The gem is available as open source under the terms of the [MIT License](https://github.com/cadenza-tech/omniauth-line-v2_1/blob/main/LICENSE.txt).

## Code of Conduct

Everyone interacting in the OmniauthLineV2.1 project's codebases, issue trackers, chat rooms and mailing lists is expected to follow the [code of conduct](https://github.com/cadenza-tech/omniauth-line-v2_1/blob/main/CODE_OF_CONDUCT.md).

## Sponsor

You can sponsor this project on [Patreon](https://patreon.com/CadenzaTech).
