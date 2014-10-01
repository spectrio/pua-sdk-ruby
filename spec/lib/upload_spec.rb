require 'spec_helper'

describe "mule upload mocker" do

  it "should create item and audio_file" do
    client = get_pua_client
    client.croak_on_404 = true
    coll = client.get_my_uploads

    item = client.create_item(coll, {
      title: 'this is a test item'
    })
    puts "item:"
    puts pp item

    af = client.create_audio_file(item)
    upload = client.start_upload(item, af.id, {
      :filename => 'example-upload.mp3',
      :size     => '92945',
      :lastmod  => '1401309036',
      :mime_type => 'image/jpeg',

    })

    # only actually upload if env var set
    if ENV['DO_S3_UPLOAD']

    else
       # pretend

    end

    client.finish_upload(upload)
  end

end
    
