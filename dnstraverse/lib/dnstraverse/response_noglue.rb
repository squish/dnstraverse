module DNSTraverse
  
  class Response::NoGlue < Response
    
    attr_reader :qname, :qclass, :qtype, :ip, :bailiwick, :server
    
    def initialize(args)
      # we queried @ip about @qname/@qclass/@qtype and received @server as a
      # referral in bailiwick @bailiwick but without any glue
      @qname = args[:qname]
      @qclass = args[:qclass]
      @qtype = args[:qtype]
      @bailiwick = args[:bailiwick]
      @ip = args[:ip]
      @server = args[:server]
      @decoded_query = nil
      @infocache = nil
      @starters = nil
      @starters_bailiwick = nil
      @status = :noglue
      update_stats_key
      return self
    end
    
    def method_missing(key, *args, &block)
      super # there are no missing methods, we answer directly
    end
    
    def update_stats_key
      @stats_key = "key:#{@ip}:#{@status}:#{@qname}:#{@qclass}:#{@qtype}:#{@server}:#{@bailiwick}"
    end
    
    def to_s
      return "No glue for #{@server}"
    end
    
  end
  
end