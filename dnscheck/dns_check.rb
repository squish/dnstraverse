require 'Dnsruby'
require 'Dnsruby/TheLog'

require 'log'

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
          if a[c] and a[c].to_s != msg.question[0].send(c).to_s then
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
      a = args.dup
      a[:qclass]||= 'IN'
      ans = msg.answer.select { |x| x.name.to_s == a[:qname] && 
        x.klass == a[:qclass] && x.type == a[:qtype]
      }
      return ans.size > 0 ? ans : nil
    end
    
    def msg_additional?(msg, args)
      qclass = args[:qclass] || 'IN'
      #      puts msg.additional.map { |x|
      #        Log.debug { "Additional: #{x.name.to_s} vs #{args[:qname].inspect}" }
      #        Log.debug { "  Additional: #{x.klass.inspect} vs #{qclass.inspect}" }
      #        Log.debug { "  Additional: #{x.type.inspect} vs #{args[:qtype].inspect}" }
      #         (x.name.to_s == args[:qname] && x.klass == qclass && x.type == args[:qtype]) ? "true" : "false"
      #      }.join("xxx")
      ans = msg.additional.select { |x|
        x.name.to_s == args[:qname] && x.klass == qclass && x.type == args[:qtype]
      }
      return ans.size > 0 ? ans : nil
    end
    
    def msg_referrals(msg)
      return msg.authority.select { |x| x.type == 'NS' && x.klass == 'IN' }
    end
    
    def msg_follow_cnames(msg)
      name = msg.question[0].qname.to_s
      while ans = msg_answers?(msg, :qname => name, :qtype => 'CNAME') do
        Log.debug { "CNAME encountered from #{name} to #{ans[0].domainname}"}
        name = ans[0].domainname.to_s
      end
      return name
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
          Log.debug { "Looking for root #{root} type #{type}" }
          if (add = msg_additional?(msg, :qname => root, :qtype => type)) then
            rootip = add[0].rdata.to_s
            Log.debug { "Using additional section found #{rootip}"}
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
      Log.debug { "run entry " + r.to_s }
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
        Log.debug { "Unexpectedly nothing to do for #{r}"}
      end
    end
    
    def find_all_roots(args)
      root = args[:root] || 'localhost'
      rootip = args[:rootip] || '127.0.0.1'
      aaaa = args[:aaaa] || false
      Log.debug { "find_roots entry #{root}" }
      # use our initial root to find all the roots
      r = Referral.new(:refid => '0', :server => nil,
      :qname => 'www.google.com', :qtype => 'A', :nsatype => aaaa ? 'AAAA' : 'A',
      :roots => [ { :name => root, :ips => [rootip] } ],
      :resolver => @resolver)
      run(r)
      Log.debug { "find_roots exit" }
    end
  end
  
  class Referral
    include MessageUtility
    
    attr_reader :server, :serverips, :qname, :qclass, :qtype, :nsatype, :msg
    attr_reader :roots, :refid
    
    def to_s
      ips = ""
      ips+= @serverips.join(',') if @serverips
      return "#{@refid} [#{@qname}/#{@qclass}/#{@qtype}] #{@server} " +
      "ips=#{ips}"
    end
    
    def initialize(args)
      @resolver = args[:resolver] # Dnsruby::Resolver object
      @qname = args[:qname]
      @qclass = args[:qclass] || :IN
      @qtype = args[:qtype] || :A
      @nsatype = args[:nsatype] || :A
      # XXX this cache should be for additional records and be duplicated
      # as it goes down the tree
      @cache = args[:cache] || Array.new # XXX not used - need to do properly
      @roots = args[:roots]
      @resolves = nil
      @msg = nil
      @refid = args[:refid] || ''
      @server = args[:server] || nil # nil for the root-root server
      @serverips = args[:serverips] || nil
      @responses = Hash.new # responses/exception for each IP in @serverips
      @children = Hash.new # Array of child Referrer objects keyed by IP
      raise "Must pass Resolver" unless @resolver
    end
    
    # resolve server to serverips, return list of Referral objects to process
    def resolve(args)
      raise "This Referral object has already been resolved" if resolved?
      refid = "#{@refid}.0"
      child_refid = 1
      # TODO start lookup at better known point using cache
      for root in @roots do
        puts "THIS IS A RESOLVE: #{@server} type #{@nsatype}"
        r = Referral.new(:server => root[:name], :serverips => root[:ips],
                         :qname => @server, :qclass => 'IN', :qtype => @nsatype,
        :nsatype => @nsatype, :cache => @cache,
        :refid => "#{refid}.#{child_refid}", :resolver => @resolver,
        :roots => @roots)
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
        process_referral(args)
      else
        # special case - no server means start from the top with the roots
        process_add_roots(args)
      end
      # return a set of Referral objects that need to be processed
      return @children.values.flatten.select {|x| x.is_a? Referral}
    end
    
    def process_add_roots(args)
      refid_prefix = @refid == '' ? '' : "#{@refid}."
      refid = 1
      @children[:rootroot] = Array.new
      for root in @roots do
        r = Referral.new(:refid => "#{refid_prefix}#{refid}",
        :server => root[:name], :serverips => root[:ips],
        :qname => @qname, :qclass => @qclass, :qtype => @qtype,
        :nsatype => @nsatype, :resolver => @resolver, :roots => @roots)
        @children[:rootroot].push r
        refid+= 1
      end
    end
    
    NOERROR = Dnsruby::RCode.NOERROR
    NXDOMAIN = Dnsruby::RCode.NXDOMAIN
    
    def process_referral(args)
      Log.debug { "process_referral " + self.to_s }
      for ip in @serverips do
        @responses[ip] = m = process_referral_makequery(ip)
        next if m.is_a? Exception
        next unless m.header.rcode == NOERROR
        name = msg_follow_cnames(msg)
        next if msg_answers?(msg, :qname => name, :qtype => @qtype)
        if (refs = msg_referrals(msg)).size > 0 then
          @children[ip] = process_referral_continued(msg)
        end
      end
    end
    
    def process_referral_makequery(ip)  
      Log.debug { "Querying #{ip} for #{@qname}/#{@qtype}" }
      @resolver.nameserver = ip
      @resolver.udp_size = Dnsruby::Resolver::DefaultUDPSize # bug in Dnsruby
      begin
        @msg = @resolver.query(@qname, @qtype)
      rescue Dnsruby::ResolvTimeout => e
        return e
      end
      msg_validate(msg, :qname => @qname, :qtype => @qtype)
      msg_comment(msg, :want_recursion => false)
      return msg
    end
    
    def process_referral_continued(msg)
      # No answers, so hopefully we have some referrals
      refs = msg_referrals(msg)
      Log.debug { "Referrals: " + refs.map {|x| x.domainname.to_s }.join(", ") }
      children = Array.new
      child_refid = 1
      for ref in refs do
        name = ref.domainname.to_s
        Log.debug { "Looking for #{name} in additional data" }
        if (add = msg_additional?(msg, :qname => name,
                                  :qtype => @nsatype)) then
          referral_ips = add.map {|x| x.address.to_s }
          Log.debug { "#{name} = " + referral_ips.join(", ") }
        else
          Log.debug { "#{name} not present in additional section" }
          serverips = nil
        end
        r = Referral.new(:server => name, :serverips => referral_ips,
                         :qname => @qname, :qclass => @qclass, :qtype => @qtype,
                         :nsatype => @nsatype, :cache => @cache,
                         :refid => "#{refid}.#{child_refid}",
        :resolver => @resolver, :roots => @roots)
        children.push r
        child_refid+= 1
      end
      return children
    end
    
  end
end