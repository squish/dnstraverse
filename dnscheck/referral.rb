module DNSCheck
  
  class Referral
    include MessageUtility
    
    attr_reader :server, :serverips, :qname, :qclass, :qtype, :nsatype
    attr_reader :refid, :message, :infocache, :parent, :bailiwick, :stats
    
    def to_s
      ips = ""
      ips+= @serverips.join(',') if @serverips
      return "#{@refid} [#{@qname}/#{@qclass}/#{@qtype}] server=#{@server} " +
      "server_ips=#{ips} bailiwick=#{@bailiwick}"
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
      @infocache = args[:infocache] || DNSCheck::InfoCache.new
      @roots = args[:roots]
      @resolves = nil
      @message = nil # our message for this particular referral question
      @refid = args[:refid] || ''
      @server = args[:server] || nil # nil for the root-root server
      @serverips = args[:serverips] || nil
      @responses = Hash.new # responses/exception for each IP in @serverips
      @responses_infocache = Hash.new # end cache for each IP
      @responses_bad = Hash.new # out of bailiwick records for each IP
      @children = Hash.new # Array of child Referrer objects keyed by IP
      @bailiwick = args[:bailiwick] || nil
      @secure = args[:secure] || true # ensure bailiwick checks
      @parent = args[:parent] || nil # Parent Referral
      @noglue = false # flag to indicate failure due to referral without glue
      @referral_resolution = args[:referral_resolution] || false # flag
      @stats = nil # will contain statistics for answers
      @stats_resolve = nil # will contain statistics for our resolve (if applic)
      @serverweights = nil # will be set if we resolve (Hash, key is IP)
      raise "Must pass Resolver" unless @resolver
      @infocache.add_hints('', args[:roots]) if args[:roots] # add root hints
      Log.debug { "New resolver object created: " + self.to_s }
    end
    
    def get_startservers(args)
      domain = args[:domain]
      ourinfocache = args[:infocache] || @infocache
      newbailiwick = nil
      # search for best NS records in authority cache based on this domain name
      ns = ourinfocache.get_ns?(domain)
      unless ns then
        # shouldn't happen because infocache should have been populated with
        # root servers
        raise "No nameservers available for #{domain} -- no root hints set??"
      end
      starters = Array.new
      # look up in additional cache corresponding IP addresses if we know them
      for rr in ns do
        iprrs = ourinfocache.get?(:qname => rr.domainname, :qtype => @nsatype)
        ips = iprrs ? iprrs.map {|iprr| iprr.address.to_s } : nil
        starters.push({ :name => rr.domainname, :ips => ips })
      end
      newbailiwick = ns[0].name
      Log.debug { "For domain #{domain} using start servers: " +
        starters.map { |x| x[:name] }.join(', ') }
      return starters, newbailiwick
    end
    
    # resolve server to serverips, return list of Referral objects to process
    def resolve(args)
      raise "This Referral object has already been resolved" if resolved?
      if @bailiwick and @server.to_s =~ /.#{@bailiwick}$/i then
        # foo.net IN NS ns.foo.net - no IP cached & no glue = failure
        Log.debug { "Attempt to resolve #{@server} with a bailiwick referral " +
                    " of #{bailiwick} - no glue record provided" }
        @noglue = true
        return Array.new
      end
      refid = "#{@refid}.0"
      child_refid = 1
      starters, newbailiwick = get_startservers(:domain => @server)
      Log.debug { "Resolving #{@server} type #{@nsatype} " }
      for starter in starters do
        r = make_referral(:server => starter[:name],
                          :serverips => starter[:ips],
                          :referral_resolution => true,
                          :qname => @server, :qclass => 'IN',
        :qtype => @nsatype, :bailiwick => newbailiwick,
        :refid => "#{refid}.#{child_refid}")
        @resolves||= Array.new
        @resolves.push r
        child_refid+= 1
      end
      # return a set of Referral objects that need to be processed
      return @resolves
    end
    
    def resolve_calculate
      Log.debug { "Calculating resolution: #{self}" }
      # create stats_resolve containing all the statistics of the resolution
      @stats_resolve = Hash.new
      if @noglue then # referral without glue - error
        outcome = "noglue"
        key = "key:#{outcome}:#{server}:#{qname}:#{qclass}:#{qtype}".downcase
        @stats_resolve[key] = { :prob => 1.0, :server => @server,
          :qname => qname, :qclass => qclass, :qtype => qtype,
          :outcome => outcome, :referral => self }
      else
        # normal resolve - combine children's statistics in to @stats_resolve
        stats_calculate_children(@stats_resolve, @resolves, 1.0)
      end
      # now use this data to work out %age of each IP address returned
      @serverweights = Hash.new
      @stats_resolve.each_pair do |key, data|
        if data[:answers] then
          # there were some answers - so add the probabilities in
          for rr in data[:answers] do
            @serverweights[rr.address.to_s]||= 0
            @serverweights[rr.address.to_s]+= data[:prob]
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
        return
      end
      for ip in @serverips do
        # set serverweight from resolution phase or use fixed weights
        serverweight = @serverweights ? @serverweights[ip] : (1.0 / @serverips.length)
        if ip =~ /^key:/ then # resolve failed for some reason
          # pull out the statistics on the resolution and copy over
          if not @stats[ip] then
            # just copy the resolve error statistics for this key
            @stats[ip] = @stats_resolve[ip].dup
            @stats[ip][:prob]*= serverweight
          else
            @stats[ip][:prob]+= @stats_resolve[ip][:prob] * serverweight
          end
          next
        end
        key = nil
        if @responses[ip] then
          msg = @responses[ip]
          qtype = msg.question[0].qtype
          qclass = msg.question[0].qclass
          qname = msg_follow_cnames(msg, :qname => msg.question[0].qname,
                                    :qtype => qtype)
          ans = nil
          # check all the immediate (non-referral) conditions
          q = "#{ip}:#{qname}:#{qclass}:#{qtype}"
          if msg.is_a? Exception then
            outcome = "exception"
            key = "key:#{outcome}:#{q}:#{msg}".downcase
          elsif msg.header.rcode != NOERROR then
            outcome = "error"
            key = "key:#{outcome}:#{q}:#{msg.header.rcode}".downcase
          elsif (ans = msg_answers?(msg, :qname => qname, :qtype => qtype)) then
            outcome = "answer"
            key = "key:#{outcome}:#{q}".downcase
          elsif msg_nodata?(msg) then
            outcome = "nodata"
            key = "key:#{outcome}:#{q}".downcase
          end
        end
        if key then
          # immediate (non-referral) conditions - no children
          @stats[key] = { :prob => serverweight, :server => @server,
            :ip => ip, :qname => qname, :qclass => qclass, :qtype => qtype,
            :msg => msg, :outcome => outcome, :answers => ans,
            :referral => self }
        else
          stats_calculate_children(@stats, @children[ip], serverweight)
        end
      end
      @stats.each_pair do |key, data|
        Log.debug { sprintf "Answer: %.2f%% %s\n", data[:prob] * 100, key }
      end
    end
    
    def processed?
      @children.size > 0 ? true : false
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
      return @children.values.flatten.select {|x| x.is_a? Referral}
    end
    
    def process_add_roots(args)
      Log.debug { "Special case processing, addding roots as referrals" }
      refid_prefix = @refid == '' ? '' : "#{@refid}."
      refid = 1
      starters = (get_startservers(:domain => ''))[0]
      @children[:rootroot] = Array.new # use 'rootroot' instead of IP address
      for root in starters do
        r = make_referral(:server => root[:name], :serverips => root[:ips],
                          :refid => "#{refid_prefix}#{refid}")
        @children[:rootroot].push r
        refid+= 1
      end
    end
    
    NOERROR = Dnsruby::RCode.NOERROR
    NXDOMAIN = Dnsruby::RCode.NXDOMAIN
    
    # Are we done?  If so, what was the reason?
    # :exception - there was an exception (timeout)
    # :error - there was a DNS error (see rcode)
    # :answered - there was a direct answer
    # :nodata - there was NODATA (referring to after cname processing)
    # :additional - answer was gleened from additional processing cache
    # false - we didn't find the answer with this message, referrals present
    def done?(msg)
      qtype = msg.question[0].qtype
      qname = msg_follow_cnames(msg, :qname => msg.question[0].qname,
                                :qtype => qtype)
      return :exception if msg.is_a? Exception
      return :error if msg.header.rcode != NOERROR
      return :answered if msg_answers?(msg, :qname => qname, :qtype => qtype)
      return :nodata if msg_nodata?(msg)
      return false
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
    
    # TODO: create response object encapsulating message, infocache and children?
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
        next if ip =~ /^key:/ # resolve failed on something
        @responses[ip] = m = process_normal_makequery(ip)
        next if m.is_a? Exception
        next if m.header.rcode != NOERROR
        @responses_infocache[ip] = newinfocache = InfoCache.new(@infocache)
        good, bad = msg_cacheable(m, @bailiwick, :both)
        @responses_bad[ip] = bad
        newinfocache.add(@secure ? good : good + bad)
        done = done?(m)
        Log.debug { "Done due to: " + done.to_s } if done
        next if done
        name = msg_follow_cnames(m, :qname => @qname, :qtype => @qtype)
        # refs = msg_referrals(m, :bailiwick => @secure ? @bailiwick : nil)
        # XXX issue warning if refs are not the same as what we're doing!
        starters, newbailiwick = get_startservers(:domain => name,
                                                  :infocache => newinfocache)
        #raise "Assertion failed for non zero referrals" if refs.size < 1
        @children[ip] = make_referrals(:starters => starters, :qname => name,
                                       :bailiwick => newbailiwick,
                                       :infocache => newinfocache)
      end
    end
    
    def make_referrals(args) # :starters can be @root or our own list
      starters = args[:starters]
      children = Array.new
      child_refid = 1
      for starter in starters do
        refargs = { :server => starter[:name], :serverips => starter[:ips],
          :refid => "#{refid}.#{child_refid}"
        }.merge(args)
        children.push make_referral(refargs)
        child_refid+= 1
      end
      return children
    end
    
    def process_normal_makequery(ip)  
      Log.debug { "Querying #{ip} for #{@qname}/#{@qtype}" }
      @resolver.nameserver = ip
      @resolver.udp_size = Dnsruby::Resolver::DefaultUDPSize # bug in Dnsruby
      begin
        @message = @resolver.query(@qname, @qtype)
      rescue Dnsruby::ResolvTimeout => e
        return e
      end
      if @message.nil? then
        puts "ERROR: Querying #{ip} for #{@qname}/#{@qtype}"
        return Dnsruby::ResolvTimeout.new
      end
      msg_validate(@message, :qname => @qname, :qtype => @qtype)
      msg_comment(@message, :want_recursion => false)
      return @message
    end
    
    def make_referral(args)
      raise "Must pass new refid" unless args[:refid]
      refargs = { :qname => @qname, :qclass => @qclass,
        :qtype => @qtype, :nsatype => @nsatype, :infocache => @infocache,
        :referral_resolution => @referral_resolution,
        :resolver => @resolver, :parent => self }.merge(args)
      return Referral.new(refargs)
    end
    
    
  end
  
end
