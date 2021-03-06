class AuthenticatorConfig
  # rubocop:disable Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity
  def env_param(name, kwargs = {})
    default = kwargs.key?(:default) ? kwargs[:default] : nil
    required = kwargs.key?(:required) ? kwargs[:required] : true

    if ENV.key? name
      if block_given?
        begin
          yield ENV[name]
        rescue StandardError => e
          puts "Error! Failed to process parameter #{name}: #{e.message}"
          exit 1
        end
      else
        ENV[name]
      end
    elsif required
      puts "Error! Parameter #{name} required#{kwargs[:extra_message]}!"
      exit 1
    else
      default
    end
  end
  # rubocop:enable Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity

  # rubocop:disable Metrics/CyclomaticComplexity
  def param_to_bool(v)
    return true if v == true || v =~ /^(true|t|yes|y|1)$/i
    return false if v == false || v.nil? || v.empty? || v =~ /^(false|f|no|n|0)$/i
    raise ArgumentError, "invalid value for Boolean: \"#{v}\""
  end
  # rubocop:enable Metrics/CyclomaticComplexity

  def initialize
    setup_public_url
    setup_authentication
    setup_sessions
    setup_saml
  end

  attr_reader  :public_url
  attr_reader  :sessions_backend
  attr_reader  :saml_settings
  attr_reader  :saml_attributes

  def authentication_required?
    @authentication_required
  end

  def slo_disabled?
    @slo_disabled
  end

  def deep_freeze
    IceNine.deep_freeze self
  end

  def sessions_settings
    expires = env_param 'SESSION_EXPIRE_AFTER', default: 600, required: false do |v|
      Integer(v)
    end
    store = if (memcache_servers = env_param('SESSION_MEMCACHE_SERVERS', required: false))
              namespace = env_param 'SESSION_MEMCACHE_NAMESPACE', default: 'sessions', required: false
              Moneta.new(:Memcached, expires: expires, server: memcache_servers, namespace: namespace)
            elsif env_param('DATABASE_URL', required: false)
              require 'mysql2'
              require 'sinatra/activerecord'

              Moneta.new(:ActiveRecord, expires: expires)
            elsif env_param('REDIS_URL', required: false)
              Moneta.new(:Redis, expires: expires)
            else
              Moneta.new(:Memory, expires: expires)
            end

    @sessions_settings.merge(store: store)
  end

  private

  def setup_public_url
    @public_url = env_param('PUBLIC_URL').gsub(%r{\/*$}, '') + '/'
  end

  def setup_authentication
    @authentication_required = env_param 'AUTHENTICATION_REQUIRED', required: false, default: true do |param|
      param_to_bool(param)
    end
  end

  def setup_sessions
    @sessions_backend = Rack::Session::Moneta

    @sessions_settings = {}
    @sessions_settings[:key] = env_param 'SESSION_COOKIE_NAME', default: 'saml', required: false
    @sessions_settings[:secure] = public_url.start_with? 'https://'

    session_domain = env_param 'SESSION_DOMAIN', required: false
    @sessions_settings[:domain] = session_domain unless session_domain.nil?

    session_secret = env_param 'SESSION_SECRET', required: false
    @sessions_settings[:secret] = session_secret unless session_secret.nil?
  end

  def setup_saml
    @saml_settings = OneLogin::RubySaml::Settings.new

    setup_saml_logger
    setup_saml_sp
    setup_saml_security
    setup_saml_name_identifier_format
    setup_saml_idp
    setup_saml_attributes
    setup_saml_slo
  end

  def setup_saml_logger
    OneLogin::RubySaml::Logging.logger.level = Logger::WARN
  end

  def setup_saml_sp
    @saml_settings.issuer = public_url + 'saml/metadata'

    @saml_settings.assertion_consumer_service_url = public_url + 'saml/acs'
    @saml_settings.assertion_consumer_service_binding = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'

    @saml_settings.single_logout_service_url = public_url + 'saml/sls'
    @saml_settings.single_logout_service_binding = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'
  end

  # rubocop:disable Metrics/AbcSize
  def setup_saml_security
    @saml_settings.certificate = env_param 'CERTIFICATE', required: false do |file|
      File.read(file)
    end
    @saml_settings.private_key = env_param('PRIVATE_KEY',
                                           required: !!@saml_settings.certificate,
                                           extra_message: ' if SP_CERTIFICATE is passed') do |file|
      File.read(file)
    end

    @saml_settings.idp_cert_fingerprint_algorithm = XMLSecurity::Document::SHA256

    @saml_settings.security = {}
    @saml_settings.security[:authn_requests_signed] = !!@saml_settings.certificate
    @saml_settings.security[:logout_requests_signed] = !!@saml_settings.certificate
    @saml_settings.security[:logout_responses_signed] = !!@saml_settings.certificate
    @saml_settings.security[:metadata_signed] = !!@saml_settings.certificate

    @saml_settings.security[:embed_sign] = true

    @saml_settings.security[:digest_method] = XMLSecurity::Document::SHA256
    @saml_settings.security[:signature_method] = XMLSecurity::Document::RSA_SHA256
  end
  # rubocop:enable Metrics/AbcSize

  def setup_saml_name_identifier_format
    @saml_settings.name_identifier_format = env_param(
      'NAME_IDENTIFIER_FORMAT',
      required: false,
      default: 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified'
    ) do |format|
      {
        'unspecified' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
        'email' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
        'persistent' => 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
        'transient' => 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient'
      }.fetch(format)
    end
  end

  def setup_saml_idp
    @saml_settings.idp_sso_target_parse_binding_priority =
      @saml_settings.idp_slo_target_parse_binding_priority =
        ['urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST', 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect']

    if (idp_metadata_url = env_param('IDP_METADATA_URL', required: false))
      idp_metadata_parser = OneLogin::RubySaml::IdpMetadataParser.new

      begin
        @saml_settings = idp_metadata_parser.parse_remote idp_metadata_url, true, settings: @saml_settings
      rescue StandardError => e
        puts "Error! Failed to parse IDP metadata #{idp_metadata_url}: #{e.message}"
        exit 1
      end
    else
      puts "Warning! IDP_METADATA_URL not passed, please configure IDP and pass IDP_METADATA_URL. SP metadata: #{public_url}saml/metadata"
    end
  end

  def setup_saml_attributes
    @saml_attributes = env_param 'ATTRIBUTES', default: {}, required: false do |str|
      str.split(':').each_slice(3).map { |n, i_n, t| [n, i_n.empty? ? n : i_n, { 's' => 'single', 'm' => 'multi' }.fetch(t)] }
    end
  end

  def setup_saml_slo
    @slo_disabled = env_param 'SLO_DISABLED', required: false, default: false do |param|
      param_to_bool(param)
    end
  end
end
