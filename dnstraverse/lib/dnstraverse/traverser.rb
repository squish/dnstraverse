gem 'dnsruby', '>1.16'
require 'dnsruby'
require 'dnstraverse/info_cache'
require 'dnstraverse/log'
require 'dnstraverse/message_utility'
require 'dnstraverse/caching_resolver'
require 'dnstraverse/referral'
require 'socket'

module DNSTraverse
  
  TYPE_ARRAY_AAAA = ['AAAA', 'A'].freeze
  TYPE_ARRAY_A = ['A'].freeze
  
  class Traverser
    include MessageUtility
    
    def progress_null(args)
    end
    
    def initialize(args)
      Socket.do_not_reverse_lookup = true
      Log.level = args[:loglevel] if args[:loglevel]
      Log.debug { "Initialize with args: " + args.inspect }
      Dnsruby.log.level = args[:libloglevel] if args[:libloglevel]
      @state = args[:state] || nil
      @maxdepth = args[:maxdepth] || 10
      @progress_main = args[:progress_main] || method(:progress_null)
      @progress_resolve = args[:progress_resolve] || method(:progress_null)
      @fast = args[:fast] || false # use fast algorithm, less accurate
      @answered = @fast ? Hash.new : nil # for fast algorithm
      retries = args[:retries] || 2
      retry_delay = args[:retry_delay] || 2
      dnssec = args[:dnssec] || false
      srcaddr = args[:srcaddr] || :'0.0.0.0'
      use_tcp = args[:always_tcp] || false
      ignore_truncation = args[:allow_tcp] ? false : true
      udpsize = args[:udpsize] || 512
      cfg = Dnsruby::Config.new
      rescfg = { :nameserver => cfg.nameserver, :ndots => cfg.ndots,
        :apply_domain => false, :apply_search_list => false}
      resargs = { :config_info => rescfg, :use_tcp => use_tcp, :recurse => false,
        :retry_times => retries, :retry_delay => retry_delay, :dnssec => dnssec,
        :ignore_truncation => ignore_truncation, :src_address => srcaddr,
        :udp_size => udpsize.to_i }
      Log.debug { "Creating remote resolver object"}
      CachingResolver.use_eventmachine(false)
      @resolver = CachingResolver.new(resargs) # used for set nameservers
      @resolver.udp_size = udpsize.to_i
      Log.debug { "Creating local resolver object"}
      @lresolver = Dnsruby::Resolver.new(resargs) # left on local default
      @lresolver.udp_size = udpsize.to_i
      self
    end
    
    ### change to get_all or something?
    def get_a_root(args)
      aaaa = args[:aaaa] || false
      Log.debug { "get_a_root entry" }
      # get nameservers for root
      begin
        msg = @lresolver.query('', 'NS')
      rescue Exception => e
        puts "Failed to get roots, local resolver returned exception: #{e}"
        raise e
      end
      msg_validate(msg, :qname => '', :qtype => 'NS')
      msg_comment(msg, :want_recursion => true)
      ans1 = msg_answers?(msg, :qname => '', :qtype => 'NS')
      unless ans1 then
        raise ResolveError, "No root nameservers found"
      end
      roots = ans1.map {|x| x.domainname.to_s }
      Log.debug { "Local resolver lists: " + roots.join(', ') }
      types = aaaa ? TYPE_ARRAY_AAAA : TYPE_ARRAY_A
      # loop through all root nameservers to get an appropriate address
      for type in types do
        for root in roots do
          if (add = msg_additional?(msg, :qname => root, :qtype => type)) then
            rootip = add[0].rdata.to_s
            return root, rootip
          end
        end
      end
      Log.debug { "Nothing in additional section of help" }
      for type in types do
        for root in roots do
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
      end
      raise ResolveError, "No address could be found for any root server"
    end
    
    def run(r, args = {})
      Log.debug { "run entry, initialising stack to: " + r.to_s }
      cleanup = args[:cleanup]
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
        raise "bad stack" if stack.size > 1000
        r = stack.pop
        Log.debug { "running on stack entry #{r}" }
        case r
          when :calc_resolve
          r = stack.pop
          r.resolve_calculate
          refres = r.referral_resolution?
          p = (refres == true ? @progress_resolve : @progress_main)
          p.call(:state => @state, :referral => r, :stage => :resolve)
          stack << r # now need to process
          next
          when :calc_answer
          r = stack.pop
          r.answer_calculate
          refres = r.referral_resolution?
          p = (refres == true ? @progress_resolve : @progress_main)
          p.call(:state => @state, :referral => r, :stage => :answer)
          r.cleanup(cleanup)
          if @fast then
            key = "#{r.qname}:#{r.qclass}:#{r.qtype}:#{r.server}"
            @answered[key] = r
          end
          next
        else
          refres = r.referral_resolution?
          p = (refres == true ? @progress_resolve : @progress_main)
          p.call(:state => @state, :referral => r, :stage => :start)
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
          children = r.process({})
          if @fast then
            Log.debug { "Checking #{r} for already completed children" }
            newchildren = []
            for c in children do
              key = "#{c.qname}:#{c.qclass}:#{c.qtype}:#{c.server}"
              if @answered.key?(key)
                Log.debug { "Fast method - completed #{c}" }
                r.replace_child(c, @answered[key])
                refres = r.referral_resolution?
                p = (refres == true ? @progress_resolve : @progress_main)
                p.call(:state => @state, :referral => c, :stage => :answer_fast)
              else
                newchildren << c
              end
            end
            children = newchildren
          end
          stack.push(*children.reverse)
          next
        end
        raise "Fatal stack error at #{r} - size still #{stack.size}"
      end
    end
    
    # asks the :root/:rootip server for all the roots, fills in any missing
    # IP addresses from local resolver
    def find_all_roots(args)
      root = args[:root] || 'localhost'
      rootip = args[:rootip] || '127.0.0.1'
      aaaa = args[:aaaa] || false
      types = aaaa ? TYPE_ARRAY_AAAA : TYPE_ARRAY_A
      Log.debug { "find_roots entry #{root}" }
      @resolver.nameserver = rootip
      # query for all the root nameservers
      msg = @resolver.query('', 'NS')
      raise msg if msg.is_a? Exception
      msg_validate(msg, :qname => '', :qtype => 'NS')
      msg_comment(msg, :want_recursion => false)
      ns = msg_answers?(msg, :qname => '', :qtype => 'NS')
      return nil unless ns
      roots = Array.new
      # look at each root in turn
      for rr in ns do
        ips = []
        # find IP addresses in the additional section
        for type in types do
          iprrs = msg_additional?(msg, :qname => rr.domainname, :qtype => type)
          if iprrs then
            ips.concat iprrs.map {|iprr| iprr.address.to_s }
          end
        end
        # if none, query for the IP addresses
        unless ips then
          Log.debug { "Locally resolving root #{rr.domainname}" }
          for type in types do
            msg = @lresolver.query(rr.domainname, type)
            msg_validate(msg, :qname => rr.domainname, :qtype => type)
            msg_comment(msg, :want_recursion => true)
            iprrs = msg_answers?(msg, :qname => rr.domainname, :qtype => type)
            if iprrs then
              ips.concat iprrs.map {|iprr| iprr.address.to_s }
            end
          end
        end
        # if we still don't have any IP address, skip this root
        unless ips.size > 0 then
          Log.warn { "Failed to resolve #{rr.domainname} type #{qtype}" }
          next
        end
        roots.push({ :name => rr.domainname, :ips => ips })
      end
      Log.debug { "find_roots exit, #{roots.map { |x| x[:name] }.join(', ') }" }
      return roots
    end
    
    def run_query(args)
      qname = args[:qname]
      qtype = args[:qtype] || 'A'
      maxdepth = args[:maxdepth] || 10
      cleanup = args[:cleanup]
      Log.debug { "run_query entry qname=#{qname} qtype=#{qtype}" }
      r = Referral.new(:qname => qname, :qtype => qtype, :roots => args[:roots],
                       :maxdepth => maxdepth, :resolver => @resolver,
                       :nsatype => 'A')
      run(r, :cleanup => cleanup)
      Log.debug { "run_query exit" }
      return r
    end
    
  end
  
end