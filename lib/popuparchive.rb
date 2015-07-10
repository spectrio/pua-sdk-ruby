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
require 'xmlsimple'
require 'mime/types'

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
        #pp(env)
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

      # normalize host
      @host.gsub!(/\/$/, '')

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
        connection_opts: options.merge( { :ssl => {:verify => false}, } )
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
        :ssl => {:verify => false},
        :headers => {
          'User-Agent'   => @user_agent,
          'Accept'       => 'application/json',
          'Cookie'       => @cookies
        }
      }
      @token = get_oauth_token
      #puts "token="
      #pp(@token)
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
      @debug and pp(resp)
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
      resp = get('/collections/'+coll_id.to_s)
      return resp.http_resp.body
    end

    def get_item(coll_id, item_id)
      resp = get('/collections/'+coll_id.to_s+'/items/'+item_id.to_s)
      return resp.http_resp.body
    end

    def get_audio_file(item, audio_file_id)
      item = get_item(item.collection_id, item.id)
      audio_file = nil
      item.audio_files.each do |af|
        if af.id == audio_file_id
          audio_file = af
          break
        end
      end
      audio_file
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
      #puts "audio_file:"
      #puts pp resp
      return resp.http_resp.body
    end

    def upload_audio_file(item, attrs={}, filepath)
      af = create_audio_file(item, attrs)
      upload = start_upload(item, af.id, {
        :filename => File.basename(filepath),
        :size     => File.size(filepath),
        :lastmod  => File.mtime(filepath).to_i,
        :mime_type => MIME::Types.type_for(filepath)[0]
      })
      upload.put( filepath )
      finish_upload(upload)
      get_audio_file(item, af.id) # re-fetch for latest values
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
      upload_to_resp = get(upload_to_uri)
      #puts "upload_to_resp:"
      #pp upload_to_resp

      sig_key = "#{item[:token]}/#{fileattrs[:filename]}"
      sig_params = { 
        :key           => sig_key,
        :mime_type     => fileattrs[:mime_type],
        :filename      => fileattrs[:filename],
        :filesize      => fileattrs[:size],
        :last_modified => fileattrs[:lastmod],
        :item_id       => item.id,
        :audio_file_id => af_id,
      }
      init_sig_uri = "#{base_uri}/get_init_signature?" + Faraday::FlatParamsEncoder.encode(sig_params)
      init_sig_resp = get(init_sig_uri)
      #puts "init_sig_resp:"
      #pp init_sig_resp

      # build the authorization key
      upload_key = upload_to_resp['key']
      authz_key = "#{upload_to_resp.provider} #{upload_key}:#{init_sig_resp.signature}"

      # special agent for aws
      aws_url = "https://#{upload_to_resp.bucket}.s3.amazonaws.com/#{sig_key}"
      aws_opts = { 
        :headers => {
          'User-Agent' => @user_agent,
          'Authorization' => authz_key,
          'x-amz-date' => init_sig_resp.date,
        },
        :ssl => { :verify => false }   
      }   
      aws_agent = Faraday.new(aws_opts) do |faraday|
        [:mashify, :xml, :raise_error].each{|mw| faraday.response(mw) }
        faraday.response :logger if @debug
        faraday.adapter  :excon   # IMPORTANT this is last
      end

      # post to provider to get the upload_id
      #puts "aws_agent.post"
      aws_resp = aws_agent.post do |req|
        req.url "#{aws_url}?uploads"
        req.headers['Content-Type'] = fileattrs[:mime_type]
        req.headers['Content-Disposition'] = "attachment; filename=" + fileattrs[:filename]
        req.headers['x-amz-acl']  = 'public-read'  # TODO
      end
      #puts "aws response:"
      #pp aws_resp

      # pull out the AWS uploadId
      sig_params[:upload_id] = aws_resp.body.InitiateMultipartUploadResult.UploadId

      # how many chunks do we expect?
      sig_params[:num_chunks] = fileattrs.has_key?(:num_chunks) ? fileattrs[:num_chunks] : 1
     
      all_sig_resp = get("#{base_uri}/get_all_signatures?" + Faraday::FlatParamsEncoder.encode(sig_params))
      #puts "all_sig_resp"
      #pp all_sig_resp

      return PopUpArchive::Upload.new( 
        :signatures => all_sig_resp.http_resp.body,
        :params     => sig_params, 
        :fileattrs  => fileattrs,
        :upload_to  => upload_to_resp.http_resp.body,
        :init_sig   => init_sig_resp.http_resp.body,
        :aws_url    => aws_url,
        :aws_agent  => aws_agent,
        :pua_client => self,
      )
      
    end

    def finish_upload(upload)
      #puts "finish_upload:"
      #pp upload

      # workflow assumes file has been successfully PUT to AWS

      # sanity check upload object
      if !upload.is_a?(PopUpArchive::Upload)
        raise "Upload object not a PopUpArchive::Upload instance"
      end


      # (1) GET aws_url?uploadId=$uploadId
      # parse xml response for ListPartsResult

      aws_upload_id = upload.params[:upload_id]
      aws_agent = upload.aws_agent
      list_authz_str = "#{upload.upload_to['provider']} #{upload.upload_to['key']}:#{upload.signatures['list_signature'][0]}"
      parts_resp = aws_agent.get upload.aws_url, {:uploadId => aws_upload_id} do |req|
        req.headers['Authorization'] = list_authz_str
        req.headers['x-amz-date']    = upload.signatures['list_signature'][1]
      end

      aws_parts = []
      #pp parts_resp
      if parts_resp.body.ListPartsResult.Part.is_a?(Array)
        parts_resp.body.ListPartsResult.Part.each do |part|
          aws_parts.push( { PartNumber: part.PartNumber, ETag: part.ETag })
        end
      else
        p = parts_resp.body.ListPartsResult.Part
        aws_parts.push( { PartNumber: p.PartNumber, ETag: p.ETag } )
      end

      # (2) POST aws_url?uplaodId=$uploadId with body
      #  <CompleteMultipartUpload>
      #   <Part><PartNumber>1</PartNumber><ETag>"$etag_from_ListPartsResult"</ETag></Part>
      #  </CompleteMultipartUpload>
      # response to POST contains CompleteMultipartUploadResult with final location

      aws_parts_xml = XmlSimple.xml_out({Part: aws_parts}, {rootname: 'CompleteMultipartUpload', noattr: true})
      #puts "aws_parts_xml: #{aws_parts_xml}"
      end_authz_str = "#{upload.upload_to['provider']} #{upload.upload_to['key']}:#{upload.signatures['end_signature'][0]}"
      aws_finish_resp = aws_agent.post do |req|
        req.url "#{upload.aws_url}?uploadId=#{aws_upload_id}"
        req.headers['Authorization'] = end_authz_str
        req.headers['x-amz-date']    = upload.signatures['end_signature'][1]
        req.headers['Content-Type'] = upload.fileattrs[:mime_type].to_s
        req.headers['Content-Disposition'] = "attachment; filename=" + upload.fileattrs[:filename]
        req.body = aws_parts_xml
      end

      #puts "aws_finish_resp:"
      #pp aws_finish_resp

      # (3) GET pua_url/upload_finished/? with params:
      #  filename => $filename,
      #  filesize => $n,
      #  key      => $sig_key,
      #  last_modified => $e,
      #  upload_id => $aws_uploadId,
      get( upload.finish_url )
       
    end

  end # end Client

  class Upload
    attr_accessor :signatures, :params, :fileattrs, :upload_to, :init_sig, :aws_url, :aws_agent, :pua_client

    def initialize args
      args.each do |k,v|
        instance_variable_set("@#{k}", v) unless v.nil?
      end
    end

    def put(filepath)
      if !File.exists?(filepath)
        raise "No such file exists: #{filepath}"
      end

      if self.params[:num_chunks] == 1

        # easiest. Upload as single file
        media = Faraday::UploadIO.new(filepath, self.fileattrs[:mime_type])
        self.put_chunk( media, 1 )

      else
        # TODO upload in chunks

      end

      self

    end

    def put_chunk(media, chunkN)
      url = "#{self.aws_url}?partNumber=#{chunkN}&uploadId=#{self.params[:upload_id]}"
      resp = self.aws_agent.put do|req|
        req.url url 
        req.headers['Authorization'] = self.authz_key_for_chunk(chunkN)
        req.headers['x-amz-date']    = self.authz_date_for_chunk(chunkN)
        req.headers['Content-Type'] = self.fileattrs[:mime_type].to_s
        req.headers['Content-Disposition'] = "attachment; filename=" + self.fileattrs[:filename]
        req.body = media
      end 

      if !resp.status.to_s.match(/^2/)
        raise resp # TODO needed?
      end 

      # tell the PUA server we're done with chunks
      chunk_url = "/items/#{params[:item_id]}/audio_files/#{params[:audio_file_id]}/chunk_loaded/?key=#{params[:key]}&chunk=#{chunkN}&upload_id=#{params[:upload_id]}&filename=#{params[:filename]}&filesize=#{params[:filesize]}&last_modified=#{params[:last_modified]}"
      self.pua_client.get(chunk_url)
    end

    def authz_key_for_chunk(chunkN)
      #puts "chunk #{chunkN}"
      #pp self.upload_to

      authz_key = "#{upload_to['provider']} #{upload_to['key']}:#{signatures['chunk_signatures'][chunkN.to_s][0]}"
      authz_key
    end

    def authz_date_for_chunk(chunkN)
      signatures['chunk_signatures'][chunkN.to_s][1]
    end

    def finish_url
      "/items/#{params[:item_id]}/audio_files/#{params[:audio_file_id]}/upload_finished?key=#{params[:key]}&upload_id=#{params[:upload_id]}&filename=#{params[:filename]}&filesize=#{params[:filesize]}&last_modified=#{params[:last_modified]}"
    end

  end

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
