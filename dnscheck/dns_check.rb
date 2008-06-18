require 'Dnsruby'
require 'Dnsruby/TheLog'

require 'info_cache'
require 'log'

# TODO calculations
# TODO looping... root servers send me to m.gtld-servers.net which they don't
# give an IP address for (with our packet size)

module DNSCheck
  class ResolveError < RuntimeError
  end
  
  class NoAnswers < RuntimeError
  end
  
  class CachingResolver < Dnsruby::Resolver
    def initialize(*args)
      @cache = Hash.new
      super(*args)
    end
    def query(name, type, klass = Dnsruby::Classes.IN)
      ip = self.config.nameserver[0]
      Log.debug { "Querying #{name} to #{ip} type #{type} class #{klass}"}
      key = "#{ip}:#{name}:#{type}:#{klass}"
      if @cache.has_key?(key) then
        Log.debug { "Cache hit: #{key}" }
        return @cache[key]
      end
      msg = Dnsruby::Message.new
      msg.add_question(name, type, klass)
      q = Queue.new
      send_async(msg, q)
      id, result, error = q.pop
      @cache[key] = result
      Log.debug { "Cache store: #{key}" }
      @cache[key]
    end
  end
  
  module MessageUtility
    module_function
    
    def msg_comment(msg, args)
      if args[:want_recursion] then
        if not msg.header.ra then
          Log.warn { "#{msg.answerfrom} doesn't allow recursion" }
        end
      else
        if msg.header.ra then
          Log.warn { "#{msg.answerfrom} allows recursion" }
        end
      end
    end
    
    
    def msg_validate(msg, args)
      a = args.dup
      a[:qclass]||= 'IN'
      begin
        if msg.question.size != 1 then
          raise ResolveError, "#{msg.answerfrom} returned unexpected " +
          "question size #{msg.question.size}"
        end
        for c in [:qname, :qclass, :qtype] do
          if a[c] and
            a[c].to_s.downcase != msg.question[0].send(c).to_s.downcase then
            raise ResolveError, "#{msg.answerfrom} returned mismatched #{c} " +
          "#{msg.question[0].send(c)} instead of expected #{a[c]}"
          end
        end
      rescue => e
        Log.debug { "Failed message was: " + msg.to_s }
        raise e
      end
    end
    
    def msg_answers?(msg, args)
      qclass = args[:qclass] || 'IN'
      ans = msg.answer.select { |x|
        x.name.to_s.casecmp(args[:qname].to_s) == 0 && 
        x.klass.to_s.casecmp(qclass.to_s) == 0 &&
        x.type.to_s.casecmp(args[:qtype].to_s) == 0
      }
      Log.debug { "Answers:" + ans.size.to_s}
      return ans.size > 0 ? ans : nil
    end
    
    def msg_additional?(msg, args)
      qclass = args[:qclass] || 'IN'
      Log.debug { "Looking for #{args[:qname]}/#{args[:qtype]} in additional" }
      add = msg.additional.select { |x|
        x.name.to_s.casecmp(args[:qname].to_s) == 0 && 
        x.klass.to_s.casecmp(qclass.to_s) == 0 &&
        x.type.to_s.casecmp(args[:qtype].to_s) == 0
      }
      Log.debug { add.size > 0 ? "Found #{add.size} additional records" \
        : "No additional records for #{args[:qname]}/#{args[:qtype]}"}
      return add.size > 0 ? ans : nil
    end
    
    def msg_additional_ips?(msg, args)
      qclass = args[:qclass] || 'IN'
      Log.debug { "Looking for #{args[:qname]}/#{args[:qtype]} in additional" }
      if add = msg.additional.select { |x|
          x.name.to_s.casecmp(args[:qname].to_s) == 0 && 
          x.klass.to_s.casecmp(qclass.to_s) == 0 &&
          x.type.to_s.casecmp(args[:qtype].to_s) == 0
        } then
        ips = add.map {|x| x.address.to_s }
        Log.debug { "Found in additional #{args[:qname]} = " + ips.join(", ") }
        return ips
      end
      Log.debug { "No additional records for #{args[:qname]}/#{args[:qtype]}" }
      return nil
    end
    
    def msg_referrals(msg, args)
      r = msg.authority.select { |x|
        x.type.to_s.casecmp('NS') == 0 && x.klass.to_s.casecmp('IN') == 0
      }
      if args[:bailiwick] then
        b = args[:bailiwick]
        r = r.select { |x|
          zonename = x.name.to_s
          if cond = zonename !~ /#{@b}$/i then
            Log.debug { "Excluding lame referral #{b} to #{zonename}" }
            raise "lame"
          end
          cond
        }
      end
      Log.debug { "Referrals: " + r.map {|x| x.domainname.to_s }.join(", ") }
      return r
    end
    
    def msg_authority(msg)
      ns = []
      soa = []
      other = []
      for rr in msg.authority do
        type = rr.type.to_s
        klass = rr.klass.to_s
        if type.casecmp('NS') == 0 && klass.casecmp('IN') == 0
          ns.push rr
        elsif type.casecmp('SOA') == 0 && klass.casecmp('IN') == 0
          soa.push rr
        else
          other.push rr
        end
      end
      return ns, soa, other      
    end
    
    def msg_follow_cnames(msg, args)
      name = args[:qname]
      type = args[:qtype]
      while true do
        return name if msg_answers?(msg, :qname => name, :qtype => type)
        if not ans = msg_answers?(msg, :qname => name, :qtype => 'CNAME') then
          return name
        end
        Log.debug { "CNAME encountered from #{name} to #{ans[0].domainname}"}
        name = ans[0].domainname.to_s
      end
    end
    
    def msg_nodata?(msg)
      ns, soa, other = msg_authority(msg)
      if soa.size > 0 or ns.size == 0 then
        Log.debug { "NODATA: soa=#{soa.size} ns=#{ns.size}" }
        pp msg
        raise "no"
        return true
      end
      return false
    end
    
    def msg_cacheable(msg, bailiwick, type = :both)
      good, bad = Array.new, Array.new
      bw = bailiwick.to_s
      bwend = "." + bw
      for section in [:additional, :authority] do
        for rr in msg.send(section) do
          name = rr.name.to_s
          if bailiwick.nil? or name.casecmp(bw) == 0 or
            name =~ /#{bwend}$/i then
            good.push rr
          else
            bad.push rr
          end
        end
      end
      good.map {|x| Log.debug { "Records within bailiwick: " + x.to_s } }
      bad.map {|x| Log.debug { "Records outside bailiwick: " + x.to_s } }
      return good if type == :good
      return bad if type == :bad
      return good, bad
    end
    
  end
  
  class Resolver
    include MessageUtility
    
    def initialize(args)
      Log.level = args[:loglevel] if args[:loglevel]
      Log.debug { "Initialize with args: " + args.inspect }
      Dnsruby::TheLog.level = args[:libloglevel] if args[:libloglevel]
      @state = args[:state] || nil
      @progress = args[:progress] || nil
      retries = args[:retries] || 2
      retry_delay = args[:retry_delay] || 2
      dnssec = args[:dnssec] || false
      srcaddr = args[:srcaddr] || :'0.0.0.0'
      use_tcp = args[:always_tcp] || false
      ignore_truncation = args[:allow_tcp] ? false : true
      cfg = Dnsruby::Config.new
      rescfg = { :nameserver => cfg.nameserver, :ndots => cfg.ndots,
        :apply_domain => false, :apply_search_list => false}
      resargs = { :config_info => rescfg, :use_tcp => use_tcp, :recurse => false,
        :retry_times => retries, :retry_delay => retry_delay, :dnssec => dnssec,
        :ignore_truncation => ignore_truncation, :src_address => srcaddr }
      Log.debug { "Creating remote resolver object"}
      @resolver = CachingResolver.new(resargs) # used for set nameservers
      @resolver.udp_size = Dnsruby::Resolver::DefaultUDPSize # bug in Dnsruby
      Log.debug { "Creating local resolver object"}
      @lresolver = Dnsruby::Resolver.new(resargs) # left on local default
      @lresolver.udp_size = Dnsruby::Resolver::DefaultUDPSize # bug in Dnsruby
      self
    end
    
    ### change to get_all or something?
    def get_a_root(args)
      aaaa = args[:aaaa] || false
      Log.debug { "get_a_root entry" }
      # get nameservers for root
      msg = @lresolver.query('', 'NS')
      msg_validate(msg, :qname => '', :qtype => 'NS')
      msg_comment(msg, :want_recursion => true)
      ans1 = msg_answers?(msg, :qname => '', :qtype => 'NS')
      unless ans1 then
        raise ResolveError, "No root nameservers found: " + e.to_str
      end
      roots = ans1.map {|x| x.domainname.to_s }
      Log.debug { "Local resolver lists: " + roots.join(', ') }
      types = aaaa ? ['AAAA'] : []
      types.push 'A'
      # loop through all root nameservers to get an appropriate address
      for root in roots do
        # lets check additional section first
        for type in types do
          if (add = msg_additional?(msg, :qname => root, :qtype => type)) then
            rootip = add[0].rdata.to_s
            return root, rootip
          end
        end
      end
      Log.debug { "Nothing in additional section of help" }
      for root in roots do
        for type in types do
          Log.debug { "Resolving root #{root} type #{type}" }
          msg = @lresolver.query(root, type)
          msg_validate(msg, :qname => root, :qtype => type)
          msg_comment(msg, :want_recursion => true)
          ans2 = msg_answers?(msg, :qname => root, :qtype => type)
          if ans2 then
            rootip = ans2[0].rdata.to_s # use first one
            Log.debug { "get_a_root exit: #{root} #{rootip}" }
            return root, rootip
          end
          Log.debug { "#{root}/#{type}: No suitable answers found" }
        end
        # there was no appropriate answer for this root
      end
      raise ResolveError, "No address could be found for any root server"
    end
    
    def run(r)
      Log.debug { "run entry, initialising stack to: " + r.to_s }
      stack = Array.new
      stack << r
      while stack.size > 0 do
        Log.debug { "stack size is #{stack.size}" }
        Log.debug {
          counter = 0
          output = ""
          for entry in stack.reverse do
            output+= sprintf "%04d %s\n", counter, entry.to_s
            counter+= 1
          end
          output
        }
        raise "bad stack" if stack.size > 100
        r = stack.pop
        Log.debug { "running on stack entry #{r}" }
        case r
          when :calc_resolve
          r = stack.pop
          @progress.call(:state => @state, :referral => r)
          r.resolve_calculate
          next
          when :calc_answer
          r = stack.pop
          @progress.call(:state => @state, :referral => r)
          r.answer_calculate
          next
        else
          @progress.call(:state => @state, :referral => r)
        end
        unless r.resolved? then
          # get resolve Referral objects, place on stack with placeholder
          stack << r << :calc_resolve
          stack.push(*r.resolve({}).reverse)
          next
        end
        unless r.processed? then
          # get Referral objects, place on stack with placeholder
          stack << r << :calc_answer
          stack.push(*r.process({}).reverse)
          next
        end
        if stack.size == 0 then
          puts "All done!!!"
        end
        raise "Fatal stack error at #{r} - size still #{stack.size}"
      end
    end
    
    def find_all_roots(args)
      root = args[:root] || 'localhost'
      rootip = args[:rootip] || '127.0.0.1'
      aaaa = args[:aaaa] || false
      Log.debug { "find_roots entry #{root}" }
      # use our initial root to find all the roots
      r = Referral.new(:refid => '0', :server => nil,
      #      :qname => 'www.goolge.com', :qtype => 'A', :nsatype => aaaa ? 'AAAA' : 'A',
      :qname => 'www.squish.net', :qtype => 'A', :nsatype => aaaa ? 'AAAA' : 'A',
      :roots => [ { :name => root, :ips => [rootip] } ],
      :resolver => @resolver)
      run(r)
      Log.debug { "find_roots exit" }
    end
  end
  
  class Referral
    include MessageUtility
    
    attr_reader :server, :serverips, :qname, :qclass, :qtype, :nsatype
    attr_reader :roots, :refid, :message, :infocache
    
    def to_s
      ips = ""
      ips+= @serverips.join(',') if @serverips
      return "#{@refid} [#{@qname}/#{@qclass}/#{@qtype}] server=#{@server} " +
      "server_ips=#{ips} bailiwick=#{@bailiwick}"
    end
    
    def initialize(args)
      @resolver = args[:resolver] # Dnsruby::Resolver object
      @qname = args[:qname]
      @qclass = args[:qclass] || :IN
      @qtype = args[:qtype] || :A
      @nsatype = args[:nsatype] || :A
      @infocache = args[:infocache] || DNSCheck::InfoCache.new
      @roots = args[:roots]
      @resolves = nil
      @message = nil
      @refid = args[:refid] || ''
      @server = args[:server] || nil # nil for the root-root server
      @serverips = args[:serverips] || nil
      @responses = Hash.new # responses/exception for each IP in @serverips
      @responses_infocache = Hash.new # end cache for each IP
      @responses_bad = Hash.new # out of bailiwick records for each IP
      @children = Hash.new # Array of child Referrer objects keyed by IP
      @bailiwick = args[:bailiwick] || nil
      @secure = args[:secure] || true # ensure bailiwick checks
      raise "Must pass Resolver" unless @resolver
      Log.debug { "New resolver object created: " + self.to_s }
    end
    
    def get_startservers(args)
      domain = args[:domain]
      ourinfocache = args[:infocache] || @infocache
      starters = @roots
      newbailiwick = nil
      # search for best NS records in authority cache based on this domain name
      if ns = ourinfocache.get_ns?(domain) then
        starters = Array.new
        # look up in additional cache corresponding IP addresses if we know them
        for rr in ns do
          iprrs = ourinfocache.get?(:qname => rr.domainname, :qtype => @nsatype)
          ips = iprrs ? iprrs.map {|iprr| iprr.address.to_s } : nil
          starters.push({ :name => rr.domainname, :ips => ips })
        end
        newbailiwick = ns[0].name
      end
      Log.debug { "For domain #{domain} using start servers: " +
        starters.map { |x| x[:name] }.join(', ') }
      return starters, newbailiwick
    end
    
    # resolve server to serverips, return list of Referral objects to process
    def resolve(args)
      raise "This Referral object has already been resolved" if resolved?
      refid = "#{@refid}.0"
      child_refid = 1
      starters, newbailiwick = get_startservers(:domain => @server)
      Log.debug { "Resolving #{@server} type #{@nsatype} " }
      for starter in starters do
        r = make_referral(:server => starter[:name], :serverips => starter[:ips],
                          :qname => @server, :qclass => 'IN', :qtype => @nsatype,
        :bailiwick => newbailiwick,
        :refid => "#{refid}.#{child_refid}")
        @resolves||= Array.new
        @resolves.push r
        child_refid+= 1
      end
      # return a set of Referral objects that need to be processed
      return @resolves
    end
    
    def resolve_calculate
      
    end
    
    def answer_calculate
    end
    
    def processed?
      @children.size > 0 ? true : false
    end
    
    def resolved?
      # root-root is always resolved, otherwise check we have IP addresses
      return true if isrootroot?
      return false if @serverips.nil?
      
      # XXX
      return true
      
      # get all the Referral objects for the resolving process and check them
      Log.debug { "checking resolved?"}
      for r in @resolves do
        Log.debug { "checking: " + r.processed? }
        return false if r.processed? == false
      end
      Log.debug { "end check"}
      true
    end
    
    def isrootroot?
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
      @children[:rootroot] = Array.new
      for root in @roots do
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
    
    # TODO: create response object encapsulating message, infocache and children?
    def process_normal(args)
      Log.debug { "process " + self.to_s }
      # XXX should we check these IPs to see if we've queried them before for
      # this query?  lame server detection is currently done on the bailiwick
      # check only during referral.  Adding this check would fast-track
      # failures
      for ip in @serverips do
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
      msg_validate(@message, :qname => @qname, :qtype => @qtype)
      msg_comment(@message, :want_recursion => false)
      return @message
    end
    
    def make_referral(args)
      raise "Must pass new refid" unless args[:refid]
      refargs = { :qname => @qname, :qclass => @qclass,
        :qtype => @qtype, :nsatype => @nsatype, :infocache => @infocache,
        :resolver => @resolver, :roots => @roots }.merge(args)
      return Referral.new(refargs)
    end
    
  end
end