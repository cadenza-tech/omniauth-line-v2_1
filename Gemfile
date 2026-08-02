# frozen_string_literal: true

source 'https://rubygems.org'

gemspec

if RUBY_ENGINE == 'truffleruby' && RUBY_VERSION < '3.3'
  gem 'json', '~> 2.7.6'
else
  gem 'json'
end
gem 'multi_xml', '< 0.9' if RUBY_ENGINE == 'truffleruby' && RUBY_VERSION < '3.3'
gem 'rack', '< 3' if RUBY_VERSION < '2.6'
gem 'rake'
gem 'rspec'
gem 'rubocop'
gem 'rubocop-performance'
gem 'rubocop-rake'
gem 'rubocop-rspec'
gem 'webmock'
