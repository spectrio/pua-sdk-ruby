Gem::Specification.new do |s|
  s.name        = 'popuparchive'
  s.version     = '1.0.0'
  s.date        = '2014-09-25'
  s.rubyforge_project = "nowarning"
  s.summary     = "Ruby client for the Pop Up Archive API"
  s.description = "Ruby client for the Pop Up Archive API. See http://popuparchive.com/"
  s.authors     = ["Peter Karman"]
  s.email       = 'peter@popuparchive.com'
  s.homepage    = 'https://github.com/popuparchive/pua-sdk-ruby'
  s.files       = ["lib/popuparchive.rb"]
  s.license     = 'Apache'
  s.add_runtime_dependency "faraday"
  s.add_runtime_dependency "faraday_middleware"
  s.add_runtime_dependency "excon"
  s.add_runtime_dependency "hashie"
  s.add_runtime_dependency "oauth2"
  s.add_runtime_dependency "xml-simple"
  s.add_development_dependency "rspec"
  s.add_development_dependency "dotenv"
  s.add_development_dependency "mime-types"

end
