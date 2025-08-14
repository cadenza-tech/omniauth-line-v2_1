# frozen_string_literal: true

require_relative 'lib/omniauth/line_v2_1/version'

Gem::Specification.new do |spec|
  spec.name = 'omniauth-line-v2_1'
  spec.version = OmniAuth::LineV21::VERSION
  spec.description = 'LINE strategy for OmniAuth'
  spec.summary = 'LINE strategy for OmniAuth'
  spec.authors = ['Masahiro']
  spec.email = ['watanabe@cadenza-tech.com']
  spec.license = 'MIT'

  github_root_uri = 'https://github.com/cadenza-tech/omniauth-line-v2_1'
  spec.homepage = "#{github_root_uri}/tree/v#{spec.version}"
  spec.metadata = {
    'homepage_uri' => spec.homepage,
    'source_code_uri' => spec.homepage,
    'changelog_uri' => "#{github_root_uri}/blob/v#{spec.version}/CHANGELOG.md",
    'bug_tracker_uri' => "#{github_root_uri}/issues",
    'documentation_uri' => "https://rubydoc.info/gems/#{spec.name}/#{spec.version}",
    'funding_uri' => 'https://patreon.com/CadenzaTech',
    'rubygems_mfa_required' => 'true'
  }

  spec.required_ruby_version = '>= 2.5.0'

  gemspec = File.basename(__FILE__)
  spec.files = IO.popen(%w[git ls-files -z], chdir: __dir__, err: IO::NULL) do |ls|
    ls.readlines("\x0").map { |f| f.chomp("\x0") }.reject do |f|
      (f == gemspec) || f.start_with?(*%w[bin/ test/ spec/ features/ .git .github .editorconfig .rubocop.yml appveyor CODE_OF_CONDUCT.md Gemfile])
    end
  end
  spec.bindir = 'exe'
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ['lib']

  spec.add_dependency 'omniauth', '~> 2.0'
  spec.add_dependency 'omniauth-oauth2', '~> 1.8'
end
