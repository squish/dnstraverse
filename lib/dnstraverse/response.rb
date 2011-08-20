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
  
  # get a response to a query (or pass in the response if you already have one)
  # creates lots of stats and info, caching as much as possible
  class Response
    attr_reader :decoded_query
    attr_reader :infocache
    attr_reader :status # our status, expanding on DecodedQuery status
    attr_reader :starters, :starters_bailiwick # :referral/:restart only
    attr_reader :stats_key
    attr_reader :server
    
    # :qname, :qclass, :qtype, :ip, :bailiwick, optional :message
    def initialize(args)
      dqc_args = { :qname => args[:qname], :qclass => args[:qclass],
        :qtype => args[:qtype], :ip => args[:ip],
        :bailiwick => args[:bailiwick], :message => args[:message] }
      @decoded_query = args[:decoded_query_cache].query(dqc_args)
      @server = args[:server]
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
    
    # set the statistics key - this is used to decide when to merge statistics
    # together.  the same key = merge, different key = keep separate
    # this is why exception name/message is added for exception types
    def update_stats_key
      r = @decoded_query
      @stats_key = "key:#{@status}:#{r.ip}:#{@server}:#{r.qname}:#{r.qclass}:#{r.qtype}"
      if @stats == :exception and r.message.is_a? Exception then
        @stats_key+= ":#{r.message}"
      end
    end
    
    # clean up the workings
    def cleanup
      @infocache = nil
      ###@cacheable_good = @cacheable_bad = nil
      @starters = @starters_bailiwick = nil
      ###@auth_ns = @auth_soa = @auth_other = nil
    end
    
    def inside_bailiwick?(name)
      return true if @bailiwick.nil?
      bwend = ".#{@bailiwick}"
      namestr = name.to_s
      return true if namestr.casecmp(@bailiwick) == 0
      return true if namestr =~ /#{bwend}$/i
      return false
    end

    # enrich the decoded_query to do the cache, lame checking and get starters
    def evaluate
      @status = @decoded_query.status # use this as a base
      if @status != :exception
        # XXX order of cacheable_good is answer, authority, additional
        # perhaps we should add some checking for overlap between sections?
        @infocache.add(@decoded_query.cacheable_good)
      end
      case @decoded_query.status
      when :restart
        @starters, @starters_bailiwick = @infocache.get_startservers(@decoded_query.endname)
      when :referral
        @starters, @starters_bailiwick = @infocache.get_startservers(@decoded_query.endname)
        unless @decoded_query.bailiwick.nil? or @starters_bailiwick =~ /\.#{@decoded_query.bailiwick}$/
          @status = :referral_lame
        end
        starternames = @starters.map { |x| x[:name].to_s.downcase }
        if starternames.sort != @decoded_query.authoritynames.sort
          @decoded_query.warnings_add "Referred authority names do not match query cache expectations"
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
