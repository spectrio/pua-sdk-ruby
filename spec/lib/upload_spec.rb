require 'spec_helper'
require 'mime/types'

describe "mule upload mocker" do

  before :each do
    if !ENV['S3_UPLOAD_FILE']
      skip "set S3_UPLOAD_FILE to test upload feature"
    end
    if !ENV['UPLOAD_COLLECTION']
      skip "set UPLOAD_COLLECTION to id value to test upload feature"
    end
  end

  it "should create item and audio_file (long form)" do
    client = get_pua_client
    client.debug = ENV['PUA_DEBUG']
    client.croak_on_404 = true
    coll = client.get_collection(ENV['UPLOAD_COLLECTION'])

    item = client.create_item(coll, {
      title: 'this is a test upload item'
    })

    af = client.create_audio_file(item)

    file = ENV['S3_UPLOAD_FILE']

    # initiate the upload at PUA
    upload = client.start_upload(item, af.id, {
      :filename => File.basename(file),
      :size     => File.size(file),
      :lastmod  => File.mtime(file).to_i,
      :mime_type => MIME::Types.type_for(file)[0]

    })

    # upload the file to AWS
    upload.put( file )

    # finish the upload at PUA
    resp = client.finish_upload(upload)
    expect(resp.num_chunks).to eq resp.chunks_uploaded.strip

  end

  it "should create item and audio_file (simple form)" do
    client = get_pua_client
    client.debug = ENV['PUA_DEBUG']
    client.croak_on_404 = true
    coll = client.get_collection(ENV['UPLOAD_COLLECTION'])
    item = client.create_item(coll, {
      title: 'this is a test simple upload item'
    })  
    file = ENV['S3_UPLOAD_FILE']
    audio_file = client.upload_audio_file(item, {}, file)
    #STDERR.puts audio_file.inspect
    expect(audio_file.current_status).to be_truthy
    expect(audio_file.original).to be_nil  # we uploaded so no original value
  end

end
    
