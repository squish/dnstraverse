#!/usr/bin/env ruby

# = Summary
# Traverse the DNS from the root exploring all possible ways of
# getting to the final destination domain name.  This is the command
# line interface to DNSCheck.
#
# == Usage
# dnscheck.rb [options] DOMAIN
#    -t, --type TYPE              Select record type (A, AAAA, SRV, WKS, NS,
#                                   CNAME, SOA, PTR, HINFO, MINFO, MX, TXT, ANY)
#    -i, --initial-server HOST    Initial DNS server(default localhost)
#        --[no-]broken-roots      Use unresponsive root servers (default false)
#        --root-aaaa              Look for IPv6 addresses for root servers
#        --follow-aaaa            Only follow AAAA records for referrals
#
#        --[no-]show-progress     Display progress information (default true)
#        --[no-]show-workings     Display detailed workings (default true)
#        --[no-]show-referrals    Display referral calculations (default false)
#        --[no-]show-serverlist   Display list of servers seen (default true)
#        --[no-]show-versions     Display versions of dns servers (default true)
#        --[no-]show-summary      Display summary information (default true)
#
#    -v, --[no-]verbose           Run verbosely
#    -d, --[no-]debug             Debug mode
#    -h, --help                   Show full help
#    -V, --version                Show version and exit
#
# == Author
# James Ponder <james@squish.net>
#
# == Copyright
# Copyright (c) James Ponder 2008
# My use only; no license granted; do not distribute
#

def progress(args)
  mystate = args[:state]
  node = args[:node]
  puts node
end

if __FILE__ == $0
  require 'optparse'
  require 'ostruct'
  require 'resolv'
  require 'rdoc/usage'
  require 'pp'
  require 'dns_check'
  require 'logger'
  require 'log'
  
  types = [ :A, :AAAA, :SRV, :WKS, :NS, :CNAME, :SOA, :PTR, :HINFO, :MINFO,
  :MX, :TXT, :ANY ]
  Version = [ 0, 0, 1].freeze
  
  options = Hash.new
  options[:verbose] = false
  options[:debug] = false
  options[:type] = :a
  options[:initial] = "localhost"
  options[:broken] = false
  options[:progress] = true
  options[:summary] = true
  options[:workings] = true
  options[:referrals] = false
  options[:serverlist] = true
  options[:versions] = true
  options[:domainname] = nil
  options[:follow_aaaa] = false
  options[:root_aaaa] = false
  
  opts = OptionParser.new
  opts.banner = "Usage: #{File.basename($0)} [options] DOMAIN"  
  opts.on("-v", "--[no-]verbose") { |o| options[:verbose] = o }
  opts.on("-d", "--[no-]debug") { |o| options[:debug] = o }
  opts.on("-i", "--initial-server HOST") { |o| options[:initial] = o }
  opts.on("-t", "--type TYPE", types) { |o| options[:type] = o }
  opts.on("--[no-]broken-roots") { |o| options[:broken] = o }
  opts.on("--[no-]follow-aaaa") { |o| options[:follow_aaaa] = o }
  opts.on("--[no-]root-aaaa") { |o| options[:root_aaaa] = o }
  opts.on("--[no-]show-progress") { |o| options[:progress] = o }
  opts.on("--[no-]show-summary") { |o| options[:summary] = o }
  opts.on("--[no-]show-workings") { |o| options[:workings] = o }
  opts.on("--[no-]show-referrals") { |o| options[:referrals] = o }
  opts.on("--[no-]show-serverlist") { |o| options[:serverlist] = o }
  opts.on("--[no-]show-versions") { |o| options[:versions] = o }
  opts.on_tail("-h", "--help") { RDoc::usage }
  opts.on_tail("-V", "--version") { puts Version.join('.'); exit }
  begin
    opts.parse!
    if ARGV.size != 1 then
      raise OptionParser::ParseError, "Missing domain name parameter"
      exit
    end
    options[:domainname] = ARGV.shift
  rescue OptionParser::ParseError => e
    puts e
    RDoc::usage(1, 'Usage')
  end
  Log.level = options[:debug] ? Logger::DEBUG : Logger::UNKNOWN
  Log.debug {"Options chosen:\n" }
  Log.debug { options.map {|x,y| "  #{x}: #{y}" }.join("\n") }
  state = Hash.new
  args = { :state => state, :aaaa => options[:follow_aaaa] }
  args[:progress] = method(:progress) if options[:progress]
  #args[:summary] = method(:summary) if options[:summary]
  #args[:workings] = method(:workings) if options[:workings]
  #args[:referrals] = method(:referrals) if options[:referrals]
  #args[:serverlist] = method(:serverlist) if options[:serverlist]
  #args[:versions] = method(:versions) if options[:versions]
  args[:loglevel] = options[:debug] ? Logger::DEBUG : Logger::UNKNOWN
  dnscheck = DNSCheck.new(args)
  dnscheck.get_a_root(:aaaa => options[:root_aaaa])
  puts "ok"
  dnscheck.find_roots(:initial => options[:initial],
                      :aaaa => options[:root_aaaa] )
  dnscheck.run_query(:domainname => options[:domainname])
end
