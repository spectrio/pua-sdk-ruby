require 'spec_helper'

describe PopUpArchive::Client do
  it "should initialize sanely" do
    client = get_pua_client
  end

  it "should fetch root endpoint" do
    client = get_pua_client
    resp = client.get('/')
    #puts pp( resp )
  end

  it "should fetch the /users/me endpoint" do
    client = get_pua_client
    resp = client.get('/users/me')
    #puts pp( resp )
    puts "client application belongs to #{resp.name}"
  end
end

describe "collections" do
  it "should fetch collections" do
    client = get_pua_client
    resp = client.get('/collections')
    #puts pp( resp )
    expect(resp.collections).not_to be_empty
    expect(resp.collections.size).to eq(resp.collections.size)
    expect(resp.collections[0].title).to eq('My Uploads') # TODO always true?
    expect(resp.collections[0].storage).to be_truthy

    # specific collection
    coll = client.get('/collections/'+resp.collections[0].id.to_s)
    #puts pp(coll)
    expect(coll.title).to eq (resp.collections[0].title)

    # idiomatic
    coll_i = client.get_collection(resp.collections[0].id.to_s)
    expect(coll.title).to eq (coll_i.title)

  end

  it "should fetch items and collection/items" do
    client = get_pua_client
    resp = client.get('/collections')
    resp.collections.each do |coll|
      items = client.get("/collections/#{coll.id.to_s}/items")
      #puts pp items.items
      items.items.each do |item|
        # request directly
        #puts "fetch item #{item.id.to_s}"
        item_d = client.get("/items/#{item.id.to_s}")
        if item_d.is_success
          expect(item_d.title).to eq(item.title)
        end
      end
    end
  end 

end

