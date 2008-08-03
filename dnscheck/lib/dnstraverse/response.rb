require 'dnstraverse/info_cache'
require 'dnstraverse/log'

module DNSTraverse
  
  class Response
    include MessageUtility
    
    attr_reader :message, :bailiwick, :infocache
    attr_reader :qname, :qclass, :qtype, :ip
    attr_reader :endname
    attr_reader :status
    attr_reader :cacheable_good, :cacheable_bad
    attr_reader :auth_ns, :auth_soa, :auth_other # authority info
    attr_reader :starters, :starters_bailiwick # :referral/:restart only
    attr_reader :exception_message, :error_message # :exception/:error only
    attr_reader :answers # :answered only
    attr_reader :key
    
    def initialize(args)
      @message = m = args[:message] # the message we received
      @qname = args[:qname] || m.question[0].qname # the query name
      @qclass = args[:qclass] || m.question[0].qclass # the query class
      @qtype = args[:qtype] || m.question[0].qtype # the query type
      @ip = args[:ip] || m.answerfrom # the nameserver IP (or name if no IP)
      @bailiwick = args[:bailiwick] # the bailiwick in force
      @infocache = InfoCache.new(args[:infocache]) # our infocache
      @cacheable_good = Hash.new # in-bailiwick records
      @cacheable_bad = Hash.new # out-of-bailiwick records
      @starters = nil # initial servers for :referral/:restart
      @starters_bailiwick = nil # for initial servers for :referral/:restart
      @auth_ns = nil # NS RR records in authority section
      @auth_soa = nil # SOA RR records in authority section
      @auth_other = nil # Other RR records in authority section
      @answers = nil # Answers, if :answered
      process
      # XXX was CNAME-followed-QNAME but i don't think that's necessary
      @key = "key:#{@ip}:#{@status}:#{@qname}:#{@qclass}:#{@qtype}" # for stats
      return self
    end
    
    def inside_bailiwick(name)
      return true if @bailiwick.nil?
      bwend = ".#{@bailiwick}"
      namestr = name.to_s
      return true if namestr.casecmp(@bailiwick) == 0
      return true if namestr =~ /#{bwend}$/i
      Log.debug { "#{namestr} is not inside bailiwick #{@bailiwick}" }
      return false
    end
    
    NOERROR = Dnsruby::RCode.NOERROR
    NXDOMAIN = Dnsruby::RCode.NXDOMAIN
    
    def process
      return process_exception if @message.is_a? Exception
      @auth_ns, @auth_soa, @auth_other = msg_authority(@message)
      @cacheable_good, @cacheable_bad = msg_cacheable(@message, @bailiwick)
      @infocache.add(@cacheable_good)
      @endname = msg_follow_cnames(@message, :qname => @qname, :qtype => @qtype,
                                   :bailiwick => @bailiwick)
      return process_restart unless inside_bailiwick(@endname)
      return process_error if @message.header.rcode != NOERROR
      @answers = msg_answers?(@message, :qname => @endname, :qtype => qtype)
      return process_answered if @answers
      return process_nodata if @auth_soa.size > 0 or @auth_ns.size == 0
      return process_referral unless @auth_ns.empty?
      return process_restart
    end
    
    def process_exception
      @status = :exception
      @exception_message = @message.to_s
    end
    
    def process_restart
      @status = :restart
      @starters, @starters_bailiwick = @infocache.get_startservers(@endname)
    end
    
    def process_error
      @status = :error
      case @message.header.rcode
        when Dnsruby::RCode::FORMERR
        @error_message = "Formate error (FORMERR)"
        when Dnsruby::RCode::SERVFAIL
        @error_message = "Server failure (SERVFAIL)"
        when Dnsruby::RCode::NXDOMAIN
        @error_message = "No such domain (NXDOMAIN)"
        when NOTIMP
        @error_message = "Not implemented (NOTIMP)"
        when REFUSED
        @error_message = "Refused"
      else
        @error_message = @message.header.rcode.to_s
      end
    end
    
    def process_answered
      @status = :answered
      return self
    end
    
    def process_nodata
      @status = :nodata
      return self
    end
    
    def process_referral
      @status = :referral
      raise "There must be NS records" if @auth_ns.empty?
      @starters, @starters_bailiwick = @infocache.get_startservers(@endname)
      starternames = @starters.map { |x| x[:name].to_s.downcase }
      authoritynames = @auth_ns.map { |rr| rr.domainname.to_s.downcase }
      @status = :referral_lame if starternames.sort != authoritynames.sort
      return self
    end
    
    def to_s
      case @status
        when :error
        return "Error: #{@error_message}"
        when :exception
        return "Exception: #{@exception_message}"
        when :nodata
        return "No data"
        when :answered
        return "Answered (#{@answers.size} entries)"
        when :referral
        return "Referral"
        when :referral_lame
        authoritynames = @auth_ns.map { |rr| rr.domainname.to_s.downcase }
        return "Lame referral to #{@authoritynames}"
        when :restart
        return "Query re-start with #{@endname}"
      end
    end
  end
end