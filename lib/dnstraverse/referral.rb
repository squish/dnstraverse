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

require 'dnstraverse/response'
require 'dnstraverse/response_noglue'
require 'dnstraverse/info_cache'
require 'dnstraverse/decoded_query_cache'
require 'dnstraverse/summary_stats'

module DNSTraverse
  
  class Referral
    include MessageUtility
    
    attr_reader :server, :serverips, :qname, :qclass, :qtype, :nsatype
    attr_reader :refid, :refkey, :infocache, :parent, :bailiwick
    attr_reader :warnings, :children, :parent_ip
    attr_reader :decoded_query_cache
    attr_reader :responses
    attr_reader :stats
    
    EMPTY_ARRAY = [].freeze
    
    def txt_ips_verbose
      return '' unless @serverips
      a = @serverips.map do |ip|
        sprintf("%.1f%%=", 100 * @serverweights[ip]).concat(ip =~ /^key:([^:]+(:[^:]*)?)/ ? $1 : ip)
      end
      a.sort.join(',')
    end
    
    def txt_ips
      return '' unless @serverips
      @serverips.map { |ip|
        ip =~ /^key:/ ? @stats_resolve[ip][:response].to_s : ip
      }.sort.join(',')
    end
    
    # ips_as_array will return any IP addresses we know for this referral server
    def ips_as_array
      return EMPTY_ARRAY unless @serverips
      my_ips = []
      for ip in @serverips do
        my_ips << ip unless ip =~ /^key:/
      end
      return my_ips
    end
    
    def to_s
      return "#{@refid} [#{@qname}/#{@qclass}/#{@qtype}] server=#{@server} " +
      "server_ips=#{txt_ips()} bailiwick=#{@bailiwick}"
    end
    
    def referral_resolution?
      return @referral_resolution ? true : false
    end
    
    # Referral object represents a particular referral to a specified server
    # with given qname, qclass and qtype.
    #
    # roots can be passed in, which will be used to populate root hints in to
    # the infocache, which if not passed in will be automatically created
    #
    # server can be nil which is a special case and causes all the roots
    # to be added as child referrals (uses infocache to lookup roots)
    #
    # if the server's IP address(es) are known, they are passed in as serverips
    # otherwise, we will resolve the serverips
    #
    # referral_resolution should be set to false.  children that are a result
    # of a resolution of a referral that didn't have glue records will have
    # this set to true so that you can distringuish this detail
    def initialize(args)
      @resolver = args[:resolver] # Dnsruby::Resolver object
      @qname = args[:qname]
      @qclass = args[:qclass] || :IN
      @qtype = args[:qtype] || :A
      @nsatype = args[:nsatype] || :A
      @infocache = args[:infocache] || DNSTraverse::InfoCache.new
      @roots = args[:roots]
      @resolves = nil # Array of referral objects for resolving phase
      @refid = args[:refid] || '' # node identifier, e.g. 1.2.1
      @refkey = args[:refkey] || '' # node key, e.g. 3.4.3 (maximums)
      @server = args[:server] || nil # nil for the root-root server
      @serverips = args[:serverips] || nil
      @responses = Hash.new # responses/exception for each IP in @serverips
      @children = Hash.new # Array of child Referrer objects keyed by IP
      @bailiwick = args[:bailiwick] || nil
      @secure = args[:secure] || true # ensure bailiwick checks
      @parent = args[:parent] || nil # Parent Referral
      @parent_ip = args[:parent_ip] || nil # Parent Referral IP if applicable
      @maxdepth = args[:maxdepth] || 10 # maximum depth before error
      @decoded_query_cache = args[:decoded_query_cache]
      @referral_resolution = args[:referral_resolution] || false # flag
      @stats = nil # will contain statistics for answers
      @stats_resolve = nil # will contain statistics for our resolve (if applic)
      @serverweights = Hash.new # key is IP
      @warnings = Array.new # warnings will be placed here
      @processed = false # flag for processed? method
      @calculated = false # flag for calculated? method
      raise "Must pass Resolver" unless @resolver
      @infocache.add_hints('', args[:roots]) if args[:roots] # add root hints
      unless @decoded_query_cache then
        dcq_args = { :resolver => @resolver}
        @decoded_query_cache = DNSTraverse::DecodedQueryCache.new(dcq_args)
      end
      if serverips then # we know the server weights - we're not resolving
        for ip in serverips do
          @serverweights[ip] = 1.0 / @serverips.length
        end
      end
      Log.debug { "New resolver object created: " + self.to_s }
    end
    
    def showstats
      s = Hash.new
      ObjectSpace.each_object do |o|
        s[o.class]||= 0
        s[o.class]= s[o.class] + 1
      end
      s.sort {|a,b| a[1] <=> b[1]}.each do | c |
        puts "#{c[1]} #{c[0]}"
      end
    end
    
    # clean up the workings
    def cleanup(args = nil)
      Log.debug { "cleaning: #{self}" }
      @infocache = nil unless args and args[:infocache]
      @cacheable_good = @cacheable_bad = nil unless args and args[:cacheable]
      @starters = @starters_bailiwick = nil unless args and args[:starters]
      @auth_ns = @auth_soa = @auth_other = nil unless args and args[:auth]
      @children = nil unless args and args[:children]
      @resolves = nil unless args and args[:resolves]
      @responses = nil unless args and args[:responses]
      @decoded_query_cache = nil unless args and args[:decoded_query_cache]
      @resolver = nil unless args and args[:resolver]
    end
    
    def inside_bailiwick?(name)
      return true if @bailiwick.nil?
      bwend = ".#{@bailiwick}"
      namestr = name.to_s
      return true if namestr.casecmp(@bailiwick) == 0
      return true if namestr =~ /#{bwend}$/i
      return false
    end
    
    def noglue?
      return false if @serverips
      return false unless inside_bailiwick?(@server)
      return true
    end
    
    # resolve server to serverips, return list of Referral objects to process
    def resolve(*args)
      raise "This Referral object has already been resolved" if resolved?
      if noglue? then
        # foo.net IN NS ns.foo.net - no IP cached & no glue = failure
        Log.debug { "Attempt to resolve #{@server} with a bailiwick referral " +
                    " of #{bailiwick} - no glue record provided" }
        return Array.new
      end
      child_refid = 1
      starters, newbailiwick = @infocache.get_startservers(@server)
      Log.debug { "Resolving #{@server} type #{@nsatype} " }
      for starter in starters do
        r = make_referral(:server => starter[:name],
                          :serverips => starter[:ips],
                          :referral_resolution => true,
                          :qname => @server, :qclass => 'IN',
                          :qtype => @nsatype,
			  :bailiwick => newbailiwick,
                          :refid => "#{@refid}.0.#{child_refid}",
			  :refkey => "#{@refkey}.0.#{starters.count}")
         (@resolves||= []) << r
        child_refid+= 1
      end
      # return a set of Referral objects that need to be processed
      return @resolves
    end
    
    def resolve_calculate
      Log.debug { "Calculating resolution: #{self}" }
      # create stats_resolve containing all the statistics of the resolution
      @stats_resolve = Hash.new
      if noglue? then # in-bailiwick referral without glue
        r = DNSTraverse::Response::NoGlue.new(:qname => @qname,
                                              :qclass => @qclass,
                                              :qtype => @qtype,
                                              :server => @server,
                                              :ip => @parent_ip,
                                              :bailiwick => @bailiwick)
        @stats_resolve[r.stats_key] = { :prob => 1.0, :response => r,
          :referral => self }
      else
        # normal resolve - combine children's statistics in to @stats_resolve
        stats_calculate_children(@stats_resolve, @resolves, 1.0)
      end
      # now use this data to work out %age of each IP address returned
      @serverweights = Hash.new
      @stats_resolve.each_pair do |key, data|
        # key = IP or key:blah, data is hash containing :prob, etc.
        if data[:response].status == :answered then # RR records
          # there were some answers - so add the probabilities in
          answers = data[:response].answers # weight RRs evenly
          for rr in answers do
            @serverweights[rr.address.to_s]||= 0
            @serverweights[rr.address.to_s]+= data[:prob] / answers.length
          end
        else
          # there were no answers - use the special key and record probabilities
          @serverweights[key]||= 0
          @serverweights[key]+= data[:prob]
        end
      end
      @serverips = @serverweights.keys
      Log.debug { "Calculating resolution (answer): #{@serverips.join(',')}" }
    end
    
    def stats_calculate_children(stats, children, weight)
      percent = (1.0 / children.length) * weight
      for child in children do
        child.stats.each_pair do |key, data|
          if not stats[key] then
            # just copy the child's statistics for this key
            stats[key] = data.dup
            stats[key][:prob]*= percent
          else
            stats[key][:prob]+= data[:prob] * percent
          end
        end
      end
    end
    
    def answer_calculate
      Log.debug { "Calculating answer: #{self}" }
      @stats = Hash.new
      
      if not @server then
        # special case - rootroot, no actual IPs, just root referrals
        stats_calculate_children(@stats, @children[:rootroot], 1.0)
        @stats.each_pair do |key, data|
          Log.debug { sprintf "Answer: %.2f%% %s\n", data[:prob] * 100, key }
        end
        @calculated = true
        return
      end
      for ip in @serverips do
        serverweight = @serverweights[ip] # set at initialize or at resolve
        if ip =~ /^key:/ then # resolve failed for some reason
          # pull out the statistics on the resolution and copy over
          raise "duplicate key found" if @stats[ip] # assertion
          if @stats_resolve[ip][:prob] != serverweight then # assertion
            $stderr.puts "#{@stats_resolve[ip][:prob]} vs #{serverweight}"
            @stats_resolve[ip].each_pair do |a,b|
              $stderr.puts a
            end
            raise "unexpected probability" 
          end
          @stats[ip] = @stats_resolve[ip].dup
          next
        end
        if @children[ip] then
          stats_calculate_children(@stats, @children[ip], serverweight)
        else
          response = @responses[ip]
          @stats[response.stats_key] = { :prob => serverweight,
            :response => response, :referral => self }
        end
      end
      @stats.each_pair do |key, data|
        Log.debug { sprintf "Answer: %.2f%% %s\n", data[:prob] * 100, key }
      end
      @calculated = true
    end
    
    def processed?
      return @processed
    end
    
    def calculated?
      return @calculated
    end
    
    def resolved?
      # root-root is always resolved, otherwise check we have IP addresses
      return true if is_rootroot?
      return true if @noglue
      return false if @serverips.nil?
      return true
    end
    
    def is_rootroot?
      # rootroot is the topmost object representing an automatic referral
      # to all the root servers
      @server.nil? ? true : false
    end
    
    def process(args)
      raise "This Referral object has already been processed" if processed?
      raise "You need to resolve this Referral object" unless resolved?
      if (server) then
        process_normal(args)
      else
        # special case - no server means start from the top with the roots
        process_add_roots(args)
      end
      # return a set of Referral objects that need to be processed
      # XXX flatten really necessary?
      @processed = true
      return @children.values.flatten.select {|x| x.is_a? Referral}
    end
    
    def process_add_roots(args)
      Log.debug { "Special case processing, addding roots as referrals" }
      dot = @refid == '' ? '' : "."
      child_refid = 1
      starters = (@infocache.get_startservers('', @nsatype))[0]
      @children[:rootroot] = Array.new # use 'rootroot' instead of IP address
      for root in starters do
        r = make_referral(:server => root[:name], :serverips => root[:ips],
                          :refid => "#{@refid}#{dot}#{child_refid}",
			  :refkey => "#{@refkey}#{dot}#{starters.count}")
        @children[:rootroot].push r
        child_refid+= 1
      end
    end
    
    def check_loop?(args) # :ip, :qtype, :qname, :qclass
      parent = @parent
      until parent.nil? do
        if parent.qname.to_s == args[:qname].to_s and
          parent.qclass.to_s == args[:qclass].to_s and
          parent.qtype.to_s == args[:qtype].to_s and
          parent.serverips and parent.serverips.include?(args[:ip]) then
          exit 1 # XXX fix me
          return RuntimeError.new("Loop detected")
        end
        parent = parent.parent
      end
      return nil
    end
    
    def process_normal(args)
      Log.debug { "process " + self.to_s }
      #      if l = check_loop?(:ip => ip, :qname => @qname,
      #                         :qtype => @qtype, :qclass => @qclass) then
      #        for ip in @serverips do
      #          @responses[ip] = l
      #          done
      #          return
      #        end
      #      end
      for ip in @serverips do
        Log.debug { "Process normal #{ip}" }
        next if ip =~ /^key:/ # resolve failed on something
        m = nil
        if @refid.scan(/\./).length >= @maxdepth.to_i then
          m = RuntimeError.new "Maxdepth #{@maxdepth} exceeded"
        end
        Log.debug { "Process normal #{ip} - making response" }
        r = DNSTraverse::Response.new(:message => m, :qname => @qname,
                                      :qclass => @qclass, :qtype => @qtype,
                                      :bailiwick => @bailiwick,
                                      :infocache => @infocache, :ip => ip,
                                      :decoded_query_cache => @decoded_query_cache)
        Log.debug { "Process normal #{ip} - done making response" }
        @responses[ip] = r
        case r.status
          when :restart, :referral then
          Log.debug { "Process normal #{ip} - making referrals" }
          @children[ip] = make_referrals(:qname => r.endname,
                                         :starters => r.starters,
                                         :bailiwick => r.starters_bailiwick,
                                         :infocache => r.infocache,
                                         :parent_ip => ip)
          Log.debug { "Process normal #{ip} - done making referrals" }
          # XXX shouldn't be any children unless referrals
          #when :referral_lame then
          #@children[ip] = RuntimeError.new "Improper or lame delegation"
        end
      end
    end
    
    def make_referrals(args) # :starters can be @root or our own list
      starters = args[:starters]
      children = Array.new
      child_refid = 1
      for starter in starters do
        refargs = {
          :server => starter[:name],
          :serverips => starter[:ips],
          :refid => "#{@refid}.#{child_refid}",
	  :refkey => "#{@refkey}.#{starters.count}"
        }.merge(args)
        children.push make_referral(refargs)
        child_refid+= 1
      end
      return children
    end
    
    def make_referral(args)
      raise "Must pass new refid" unless args[:refid]
      raise "Must pass new refkey" unless args[:refkey]
      refargs = { :qname => @qname, :qclass => @qclass,
        :qtype => @qtype, :nsatype => @nsatype, :infocache => @infocache,
        :referral_resolution => @referral_resolution,
        :resolver => @resolver, :maxdepth => @maxdepth, :parent => self,
        :decoded_query_cache => @decoded_query_cache }.merge(args)
      return Referral.new(refargs)
    end
    
    def replace_child(before, after)
      @children.each_key do | ip |
        @children[ip].map! { |c| c.equal?(before) ? after : c }
      end
    end
    
    def stats_display(args)
      spacing = args[:spacing] || false
      results = args[:results] || true
      prefix = args[:prefix] || ''
      indent = args[:indent] || "#{prefix}            "
      first = true
      @stats.keys.sort!.each do | key |
        data = @stats[key]
        puts if spacing and not first
        first = false
        printf "#{prefix}%5.1f%%: ", data[:prob] * 100
        response = data[:response]
        referral = data[:referral]
        where = "#{referral.server} (#{response.ip})"
        case response.status
          when :exception
          puts "#{response.exception_message} at #{where}"
          when :noglue
          puts "No glue at #{referral.parent.server} " + 
            "(#{response.ip}) for #{response.server}"
          when :error
          puts "#{response.error_message} at #{where}"
          when :nodata
          puts "NODATA (for this type) at #{where}"
          when :answered
          puts "Answer from #{where}"
          if results then
            for rr in data[:response].answers do
              puts "#{indent}#{rr}"
            end
          end
        else
          puts "Stopped at #{where})"
          puts "#{indent}#{key}"
        end
        if response.status != :answered and
         ((response.qname != @qname) or (response.qclass != @qclass) or
         (response.qtype != @qtype)) then
          puts "#{indent}While querying #{response.qname}/" +
          "#{response.qclass}/#{response.qtype}"
        end
      end
    end

    # Returns a SummaryStats object
    def summary_stats
      return nil unless calculated?
      @summary_stats_object||= DNSTraverse::SummaryStats.new(self)
    end
    
  end
end
