#    DNSTraverse traverses the DNS to show statistics and information
#    Copyright (C) 2008 James Ponder
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, version 3 of the License.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

require 'dnstraverse/info_cache'
require 'dnstraverse/log'

module DNSTraverse
  
  class DecodedQuery
    
    include MessageUtility
    
    attr_reader :message, :bailiwick, :infocache
    attr_reader :qname, :qclass, :qtype, :ip
    attr_reader :endname
    attr_reader :status
    attr_reader :cacheable_good, :cacheable_bad
    attr_reader :auth_ns, :auth_soa, :auth_other # authority info
    attr_reader :exception_message, :error_message # :exception/:error only
    attr_reader :answers # :answered only
    attr_reader :authoritynames # auth_ns converted to array of strings
    #    attr_reader :stats_key
    
    def initialize(args)
      @message = args[:message] || nil # skip query - use this message/exception
      @qname = args[:qname] # the query name
      @qclass = args[:qclass] # the query class
      @qtype = args[:qtype] # the query type
      @ip = args[:ip] # the nameserver to query (was queried if :message passed)
      @resolver = args[:resolver] # Dnsruby::Resolver / CachingResolver object
      @bailiwick = args[:bailiwick] # the bailiwick in force
      @cacheable_good = Hash.new # in-bailiwick records
      @cacheable_bad = Hash.new # out-of-bailiwick records
      @auth_ns = nil # NS RR records in authority section
      @auth_soa = nil # SOA RR records in authority section
      @auth_other = nil # Other RR records in authority section
      @answers = nil # Answers, if :answered
      @warnings = nil # Warnings if there are any (array)
      query unless @message
      process
      return self
    end
    
    def warnings_add(warning)
      @warnings = [] unless @warnings
      if warning.is_a? Array then
        @warnings.concat warning
      else
        @warnings.push warning
      end
    end
    
    def makequery_with_udpsize(udpsize)
      @resolver.udp_size = udpsize
      return @resolver.query(@qname, @qtype)
    end
    
    # make a query
    # start with whatever UDP size is configured in resolver
    # fall-back to UDP size 512 if appropriate
    def makequery_message
      my_udp_size = @resolver.udp_size
      message = makequery_with_udpsize(my_udp_size)
      return message if message.is_a? Exception
      return message if my_udp_size == 512
      return message if (message.rcode != Dnsruby::RCode.FORMERR and
                         message.rcode != Dnsruby::RCode.NOTIMP and
                         message.rcode != Dnsruby::RCode.SERVFAIL)
      Log.debug { "Possible failure by nameserver to understand EDNS0 - retry" }
      message_retry = makequery_with_udpsize(512)
      @resolver.udp_size = my_udp_size
      return message if message_retry.is_a? Exception
      return message if (message_retry.rcode == Dnsruby::RCode.FORMERR or
                         message_retry.rcode == Dnsruby::RCode.NOTIMP or
                         message_retry.rcode == Dnsruby::RCode.SERVFAIL)
      warnings_add "#{message.answerfrom} doesn't seem to support EDNS0"
      return message_retry
    end
    
    def query
      Log.debug { "Querying #{@ip} for #{@qname}/#{@qclass}/#{@qtype}" }
      @resolver.nameserver = ip
      @message = makequery_message
      unless @message.is_a? Exception then
        msg_validate(message, :qname => @qname, :qclass => @qclass, 
                     :qtype => @qtype)
        warnings_add msg_comment(message, :want_recursion => false)
      end
      return @message
    end
    
    #    # clean up the workings
    #    def cleanup
    #      @cacheable_good = @cacheable_bad = nil
    #      @starters = @starters_bailiwick = nil
    #      @auth_ns = @auth_soa = @auth_other = nil
    #    end
    
    def inside_bailiwick?(name)
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
      @endname = msg_follow_cnames(@message, :qname => @qname, :qtype => @qtype,
                                   :bailiwick => @bailiwick)
      return process_restart unless inside_bailiwick?(@endname)
      return process_error if @message.rcode != NOERROR
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
    end
    
    def process_error
      @status = :error
      case @message.rcode
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
        @error_message = @message.rcode.to_s
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
      @authoritynames = @auth_ns.map { |rr| rr.domainname.to_s.downcase }
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
        return "Referral to #{@authoritynames.join(',')}"
        when :restart
        return "Query re-start with #{@endname}"
      end
    end
  end
end
