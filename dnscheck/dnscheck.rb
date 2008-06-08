if __FILE__ == $0
  require 'optparse'
  require 'ostruct'
  require 'resolv'
  require 'pp'
  
  types = [ :NS, :CNAME, :SOA, :PTR, :HINFO, :MINFO, :MX, :TXT, :ANY ]
  
  options = OpenStruct.new
  options.verbose = false
  options.debug = false
  options.type = :a
  options.initial = "localhost"
  
  opts = OptionParser.new do |opts|
    opts.banner = "Usage: #{File.basename($0)} [options] DOMAIN"
    
    opts.on("-v", "--[no-]verbose", "Run verbosely") do |o|
      options.verbose = o
    end
    opts.on("-d", "--[no-]debug", "Debug mode") do |o|
      options.debug = o
    end
    opts.on("-i", "--initial-server HOST",
            "Initial DNS server (default localhost)") do |o|
      options.initial = o
    end
    opts.on("--type TYPE", types,
      "Select record type (#{types.join(", ")})") do |o|
      options.type = o
    end
    opts.on_tail("-h", "--help", "Show this message") do
      puts opts
      exit
    end
    opts.on_tail("--version", "Show version") do
      puts OptionParser::Version.join('.')
      exit
    end
  end
  opts.parse!
  if ARGV.size != 1 then
    puts opts
    exit
  end
  options.filename = ARGV.shift
  pp options if options.debug
end
