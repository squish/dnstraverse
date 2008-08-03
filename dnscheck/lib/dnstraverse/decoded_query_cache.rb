require 'dnstraverse/log'
require 'dnstraverse/decoded_query'

module DNSTraverse
  
  class DecodedQueryCache

    attr_reader :requests, :cache_hits, :resolver, :cache
    
    def initialize(args)
      @resolver = args[:resolver] || raise("Must pass resolver")
      @cache = Hash.new
      @requests = 0
      @cache_hits = 0
    end
    
    def query(args)
      qname = args[:qname] || raise("Must pass qname")
      qclass = args[:qclass] || raise("Must pass qclass")
      qtype = args[:qtype] || raise("Must pass qtype")
      ip = args[:ip] || raise("Must pass ip")
      bailiwick = args[:bailiwick] # could be nil
      key = "#{ip}:#{qname}:#{qclass}:#{qtype}:#{bailiwick}"
      Log.debug { "Decoded Query Cache query #{key}" }
      if @cache.has_key?(key) then
        Log.debug { "Decoded Query Cache hit: #{key}" }
        @cache_hits+= 1
        return @cache[key]
      end
      newargs = args.merge( { :resolver => @resolver } )
      @cache[key] = DNSTraverse::DecodedQuery.new(newargs)
      Log.debug { "Decoded Query Cache store: #{key}" }
      return @cache[key]
    end
    
  end
  
end
