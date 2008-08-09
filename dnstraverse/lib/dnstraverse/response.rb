require 'dnstraverse/info_cache'
require 'dnstraverse/log'

module DNSTraverse
  
  # get a response to a query (or pass in the response if you already have one)
  # creates lots of stats and info, caching as much as possible
  class Response
    attr_reader :decoded_query
    attr_reader :infocache
    attr_reader :status # our status, expanding on DecodedQuery status
    attr_reader :starters, :starters_bailiwick # :referral/:restart only
    attr_reader :stats_key
    
    # :qname, :qclass, :qtype, :ip, :bailiwick, optional :message
    def initialize(args)
      dqc_args = { :qname => args[:qname], :qclass => args[:qclass],
        :qtype => args[:qtype], :ip => args[:ip],
        :bailiwick => args[:bailiwick], :message => args[:message] }
      @decoded_query = args[:decoded_query_cache].query(dqc_args)
      @infocache = InfoCache.new(args[:infocache]) # our infocache
      @starters = nil # initial servers for :referral/:restart
      @starters_bailiwick = nil # for initial servers for :referral/:restart
      evaluate
      update_stats_key
      return self
    end
    
    def method_missing(key, *args, &block)
      if @decoded_query.respond_to?(key) then
        return @decoded_query.send(key, *args)
      end
      super
    end
    
    def update_stats_key
      r = @decoded_query
      @stats_key = "key:#{r.ip}:#{@status}:#{r.qname}:#{r.qclass}:#{r.qtype}"
    end
    
    # clean up the workings
    def cleanup
      @infocache = nil
      ###@cacheable_good = @cacheable_bad = nil
      @starters = @starters_bailiwick = nil
      ###@auth_ns = @auth_soa = @auth_other = nil
    end
    
    # enrich the decoded_query to do the cache, lame checking and get starters
    def evaluate
      @status = @decoded_query.status # use this as a base
      if @status != :exception
        @infocache.add(@decoded_query.cacheable_good)
      end
      case @decoded_query.status
        when :restart
        @starters, @starters_bailiwick = @infocache.get_startservers(@decoded_query.endname)
        when :referral
        @starters, @starters_bailiwick = @infocache.get_startservers(@decoded_query.endname)
        starternames = @starters.map { |x| x[:name].to_s.downcase }
        if starternames.sort != @decoded_query.authoritynames.sort
          @status = :referral_lame
        end
      end
    end
    
    # convert to string - check for our enrichments, or use decoded_status
    def to_s
      case @status
        when :referral_lame
        return "Lame referral to #{@decoded_query.authoritynames}"
      else
        return @decoded_query.to_s
      end
    end
  end
end