require 'spec_helper'
require 'mime/types'

describe "mule upload mocker" do

  before :each do
    if !ENV['S3_UPLOAD_FILE']
      skip "set S3_UPLOAD_FILE to test upload feature"
    end
  end

  it "should create item and audio_file" do
    client = get_pua_client
    client.debug = true
    client.croak_on_404 = true
    coll = client.get_my_uploads

    item = client.create_item(coll, {
      title: 'this is a test item'
    })
    puts "item:"
    puts pp item

    af = client.create_audio_file(item)

    file = ENV['S3_UPLOAD_FILE']

    # initiate the upload at PUA
    upload = client.start_upload(item, af.id, {
      :filename => File.basename(file),
      :size     => File.size(file),
      :lastmod  => File.mtime(file).to_i,
      :mime_type => MIME::Types.type_for(file)[0]

    })

    puts pp upload

    # upload the file to AWS
    # TODO part of SDK? or external lib?

    # finish the upload at PUA
    client.finish_upload(upload)
  end

end
    
