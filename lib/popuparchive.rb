# Pop Up Archive Ruby SDK
# Copyright 2014 - Pop Up Archive
# Licensed under Apache 2 license - see LICENSE file
#
#

require 'rubygems'
require 'json'
require 'faraday_middleware'
require 'oauth2'
require 'uri'

module PopUpArchive

  module Error
    class NotFound < StandardError

    end
  end

  class FaradayErrHandler < Faraday::Response::Middleware
    def on_complete(env)
      # Ignore any non-error response codes
      return if (status = env[:status]) < 400
      #puts "got response status #{status}"
      case status
      when 404
        #raise Error::NotFound
        # 404 errors not fatal
      else
        #puts pp(env)
        super  # let parent class deal with it
      end
    end
  end

  class Client

    attr_accessor :host
    attr_accessor :debug
    attr_accessor :agent
    attr_accessor :user_agent
    attr_accessor :cookies
    attr_accessor :api_endpoint
    attr_accessor :croak_on_404

    def version
      return "1.0.0"
    end

    def initialize(args)
      #puts args.inspect
      @un                  = args[:username]
      @pw                  = args[:password]
      @oauth_id            = args[:id]
      @oauth_secret        = args[:secret]
      @oauth_redir_uri     = args[:redir_uri] || 'urn:ietf:wg:oauth:2.0:oob'
      @host                = args[:host] || 'https://www.popuparchive.com'
      @debug               = args[:debug]
      @user_agent          = args[:user_agent] || 'popuparchive-ruby-client/'+version()
      @api_endpoint        = args[:api_endpoint] || '/api'
      @croak_on_404        = args[:croak_on_404] || false

      # sanity check
      begin
        uri = URI.parse(@host)
      rescue URI::InvalidURIError => err
        raise "Bad :host value " + err
      end
      if (!uri.host || !uri.port)
        raise "Bad :host value " + @server
      end

      @agent = get_agent()

    end

    def get_oauth_token(options={})
      oauth_options = {
        site:            @host + @api_endpoint,
        authorize_url:   @host + '/oauth/authorize',
        token_url:       @host + '/oauth/token',
        redirect_uri:    @oauth_redir_uri,
        #connection_opts: connection_options(options)
      }

      # TODO

      client = OAuth2::Client.new(@oauth_id, @oauth_secret, oauth_options) do |faraday|
        faraday.request  :url_encoded
        faraday.response :logger if @debug
        faraday.adapter  :excon
      end

      token = nil
      if @un && @pw
        # TODO 3-legged oauth to @authorize_url
      else
        token = client.client_credentials.get_token()
      end

      return token
    end

    def get_agent()
      uri = @host + @api_endpoint
      opts = {
        :url => uri,
        :headers => {
          'User-Agent'   => @user_agent,
          'Accept'       => 'application/json',
          'Cookie'       => @cookies
        }
      }
      @token = get_oauth_token
      #puts "token="
      #puts pp(@token)
      conn = Faraday.new(opts) do |faraday|
        faraday.request :url_encoded
        [:mashify, :json].each{|mw| faraday.response(mw) }
        if !@croak_on_404
          faraday.use PopUpArchive::FaradayErrHandler
        else 
          faraday.response(:raise_error)
        end
        faraday.request :authorization, 'Bearer', @token.token
        faraday.response :logger if @debug
        faraday.adapter  :excon   # IMPORTANT this is last
      end

      return conn
    end

    def get(path, params={})
      resp = @agent.get @api_endpoint + path, params
      @debug and puts pp(resp)
      return PopUpArchive::Response.new resp
    end

    def post(path, body, content_type='application/json')
      uri = @api_endpoint + path
      resp = @agent.post do|req|
        req.url uri
        req.body = body
        req.headers['Content-Type'] = content_type
      end
      return PopUpArchive::Response.new resp
    end

    def get_or_create_item(filename)


    end

    def get_collection(coll_id)
      resp = get('/collections/'+coll_id)
      return resp.http_resp.body
    end

    def get_my_uploads
      resp = get('/collections')
      my_uploads = nil
      resp.collections.each do|coll|
        if coll.title == 'My Uploads'
          my_uploads = coll
        end
      end
      return my_uploads
    end 

    def create_item(coll, attrs)
      resp = post("/collections/#{coll.id}/items", JSON.generate(attrs))
      return resp.http_resp.body
    end
   
    def create_audio_file(item, attrs={})
      file = attrs.has_key?(:file) ? URI::encode(attrs.delete(:file)) : nil
      uri  = "/items/#{item.id}/audio_files"
      uri  += "?file=#{file}" if file
      body = JSON.generate({:audio_file => attrs})
      resp = post(uri, body)
      puts "audio_file:"
      puts pp resp
      return resp.http_resp.body
    end 

    def start_upload(item, af_id, fileattrs)
      
      # workflow is:
      # (1) GET upload_to with audio_file.id
      # (2) using response, GET get_init_signature
      #  (example: "key"=>"$token/$filename", "mime_type"=>"image/jpeg", "filename"=>"$filename", "filesize"=>"$n", "last_modified"=>"$e", "item_id"=>"$iid", "audio_file_id"=>"$afid"}
      # (3) using upload_id, GET get_all_signatures
      #  (example: {"key"=>"$token/$filename", "mime_type"=>"image/jpeg", "num_chunks"=>"1", "upload_id"=>"$upid", "filename"=>"$filename", "filesize"=>"$n", "last_modified"=>"$e", "item_id"=>"$iid", "audio_file_id"=>"$afid"}
      # (4) foreach chunk, GET chunk_loaded (optional, since only UI needs this, not a SDK)
      # (5) finally, GET upload_finished (see finish_upload() below)

      # check 'item' for validity
      if !item.has_key? :token 
        raise ":token missing on item"
      end
      if !item.has_key? :id
        raise ":id missing on item"
      end

      # check 'fileattrs' for validity
      if !fileattrs.has_key? :filename
        raise ":filename missing on fileattrs"
      end
      if !fileattrs.has_key? :lastmod
        raise ":lastmod missing on fileattrs"
      end
      if !fileattrs.has_key? :size
        raise ":size missing on fileattrs"
      end
      if !fileattrs.has_key? :mime_type
        raise ":mime_type missing on fileattrs"
      end

      base_uri = "/items/#{item.id}/audio_files/#{af_id}"

      upload_to_uri = "#{base_uri}/upload_to"
      upload_to = get(upload_to_uri)
      puts "upload_to:"
      puts pp upload_to

      sig_key = "#{item[:token]}/#{fileattrs[:filename]}"
      get_sig_uri = "#{base_uri}/get_init_signature?" + Faraday::FlatParamsEncoder.encode({
        :key           => sig_key,
        :mime_type     => fileattrs[:mime_type],
        :filename      => fileattrs[:filename],
        :filesize      => fileattrs[:size],
        :last_modified => fileattrs[:lastmod],
        :item_id       => item.id,
        :audio_file_id => af_id,
      })
      get_sig = get(get_sig_uri)
      puts "get_sig:"
      puts pp get_sig

      # build the authorization key
      upload_key = upload_to['key']
      authz_key = "#{upload_to.provider} #{upload_key}:#{get_sig.signature}"

      # special agent for aws
      aws_opts = { 
        :url => "https://#{upload_to.bucket}.s3.amazonaws.com/#{sig_key}?uploads",
        :headers => {
          'User-Agent' => @user_agent,
          'Authorization' => authz_key,
        },
        :ssl => { :verify => false }   
      }   
      aws_agent = Faraday.new(aws_opts) do |faraday|
        [:xml, :raise_error].each{|mw| faraday.response(mw) }
        faraday.response :logger if @debug
        faraday.adapter  :excon   # IMPORTANT this is last
      end

      # post to provider to get the upload_id
      puts "aws_agent.post"
      aws_resp = aws_agent.post do |req|
        req.headers['Content-Type'] = fileattrs[:mime_type]
        req.headers['Content-Disposition'] = "attachment; filename=" + fileattrs[:filename]
        # TODO
        req.headers['x-amz-date'] = get_sig.date
        req.headers['x-amz-acl']  = 'public-read'
      end
      puts "aws response:"
      puts pp aws_resp
       
      
    end

    def finish_upload(upload)
      puts "finish_upload:"
      puts pp upload

    end

  end # end Client

  # dependent classes
  class Response

    attr_accessor :http_resp

    def initialize(http_resp)
      @http_resp = http_resp

      #warn http_resp.headers.inspect
      #warn "code=" + http_resp.status.to_s

      @is_ok = false
      if http_resp.status.to_s =~ /^2\d\d/
        @is_ok = true
      end

    end

    def status()
      return @http_resp.status
    end

    def is_success()
      return @is_ok
    end

    def method_missing(meth, *args, &block)
      if @http_resp.body.respond_to? meth
        @http_resp.body.send(meth, *args, &block)
      else
        super
      end
    end

    def respond_to?(meth)
      if @http_resp.body.respond_to? meth
        true
      else
        super
      end
    end

  end # end Response

end # end module
