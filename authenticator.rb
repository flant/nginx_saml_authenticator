require 'json'
require_relative 'authenticator_config'

class Authenticator < Sinatra::Base
  register Sinatra::MultiRoute

  CONFIG = AuthenticatorConfig.new.deep_freeze

  use CONFIG.sessions_backend, CONFIG.sessions_settings

  enable :logging
  disable :protection

  def config
    CONFIG
  end

  before do
    if session.key? 'remote_addr' and session['remote_addr'] != request.ip
      logger.error "remote_addr changed"
      session.destroy
    elsif session.key? 'idp_session_expires_at' and session['idp_session_expires_at'] <= Time.now.to_i
      logger.error "idp_session_expired"
      session.destroy
    end
  end

  def saml_metadata
    @@saml_metadata ||= OneLogin::RubySaml::Metadata.new.generate(config.saml_settings, true)
  end

  get '/saml/metadata' do
    content_type 'text/xml'
    saml_metadata
  end

  route :get, :post, '/saml/auth' do
    if session['nameid']
      if session.key? 'attributes'
        encoded_attributes = Base64.strict_encode64(
          Zlib::Deflate.new(nil, -Zlib::MAX_WBITS).deflate(
            session['attributes'].to_json, Zlib::FINISH
          )
        )
      end

      headers 'Authorization' => 'Basic ' + Base64.strict_encode64("#{session['nameid']}:#{encoded_attributes}")
    elsif config.authentication_required?
      if config.saml_settings.idp_sso_target_binding == 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'
        redirect config.public_url + 'saml/login', 403
      elsif config.saml_settings.idp_sso_target_binding == 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'
        redirect OneLogin::RubySaml::Authrequest.new.create(
          config.saml_settings,
          :RelayState => config.public_url[0...-1] + env['HTTP_X_AUTH_REQUEST_ORIGINAL_URI']
        ), 403
      else
        logger.error "idp_sso_target_binding not configured"
        halt 500
      end
    end
  end

  post '/saml/acs' do
    saml_response = OneLogin::RubySaml::Response.new(params[:SAMLResponse], :settings => config.saml_settings)

    unless saml_response.is_valid?
      logger.error saml_response.errors

      halt 401
    end

    session.destroy

    session['nameid'] = saml_response.nameid
    session['remote_addr'] = request.ip 
    session['idp_session'] = saml_response.sessionindex if saml_response.sessionindex
    session['idp_session_expires_at'] = saml_response.session_expires_at if saml_response.session_expires_at

    config.saml_attributes.each do |name, internal_name, type|
      if saml_response.attributes.include? name
        (session['attributes'] ||= {})[internal_name] = saml_response.attributes.send(type, name)
      end
    end

    if params[:RelayState].nil? or params[:RelayState].empty?
      redirect config.public_url
    else
      redirect params[:RelayState]
    end
  end

  route :get, :post, '/saml/sls' do
    unless session['nameid']
      halt 401
    end

    if params[:SAMLRequest]
      logger.error "IdP initiated logout not implemented"
      halt 500
    elsif params[:SAMLResponse]
      saml_logout_response = OneLogin::RubySaml::Logoutresponse.new(params[:SAMLResponse], config.saml_settings, :matches_request_id => session['logout_request_id'], :get_params => params)

      unless saml_logout_response.validate
        logger.error saml_logout_response.errors

        halt 500
      end

      session.destroy

      if params[:RelayState].nil? or params[:RelayState].empty?
        redirect config.public_url
      else
        redirect params[:RelayState]
      end
    end
  end

  get '/saml/login' do
    if session['nameid']
      redirect request.referer || config.public_url
    else
      if config.saml_settings.idp_sso_target_binding == 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'
         erb :form, :locals => {
          :action => config.saml_settings.idp_sso_target_url,
          :params => OneLogin::RubySaml::Authrequest.new.create_params(
            config.saml_settings,
            :RelayState => request.referer
          )
        }
      elsif config.saml_settings.idp_sso_target_binding == 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'
        redirect OneLogin::RubySaml::Authrequest.new.create(
          config.saml_settings,
          :RelayState => request.referer
        )
      else
        logger.error "idp_sso_target_binding not configured"
        halt 500
      end
    end
  end

  get '/saml/logout' do
    unless session['nameid']
      halt 401
    end

    if config.slo_disabled? or config.saml_settings.idp_slo_target_url.nil?
      session.destroy

      redirect config.public_url
    else
      saml_settings = config.saml_settings.dup

      saml_settings.name_identifier_value = session['nameid']
      saml_settings.sessionindex = session['idp_session'] if session.key? 'idp_session'

      saml_logout_request = OneLogin::RubySaml::Logoutrequest.new
      session['logout_request_id'] = saml_logout_request.uuid

      if config.saml_settings.idp_slo_target_binding == 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'
        erb :form, :locals => {
          :action => saml_settings.idp_slo_target_url,
          :params => saml_logout_request.create_params(
            saml_settings,
            :RelayState => config.authentication_required? ? request.referer : nil
          )
        }
      elsif config.saml_settings.idp_slo_target_binding == 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'
        redirect saml_logout_request.create(
          saml_settings,
          :RelayState => config.authentication_required? ? request.referer : nil
        )
      else
        logger.error "idp_sso_target_binding not configured"
        halt 500
      end
    end
  end
end
