# encoding: utf-8

require 'lib/dnstraverse/version'

require 'rubygems'
require 'bundler'
begin
  Bundler.setup(:default, :development)
rescue Bundler::BundlerError => e
  $stderr.puts e.message
  $stderr.puts "Run `bundle install` to install missing gems"
  exit e.status_code
end
require 'rake'

require 'jeweler'
Jeweler::Tasks.new do |gem|
  # gem is a Gem::Specification... see http://docs.rubygems.org/read/chapter/20 for more options
  gem.name = 'dnstraverse'
  gem.summary = 'Complete DNS traversal checker'
  gem.description = File.read(File.join(File.dirname(__FILE__), 'README'))
  gem.homepage = 'http://www.squish.net/dnstraverse/'
  gem.license = "GPL"
  gem.email = 'james@squish.net'
  gem.authors = ['James Ponder']
  gem.required_ruby_version = '>=1.8'
  gem.version = DNSTraverse::Version::STRING;
  gem.files = FileList["Rakefile", "{bin,generators,lib,test}/**/*"]
  gem.extra_rdoc_files = ['README', 'LICENSE']
  gem.executables = [ 'dnstraverse' ]
  gem.has_rdoc = true
#  gem.test_files = Dir["test/test*.rb"]
  # dependencies defined in Gemfile
end
Jeweler::RubygemsDotOrgTasks.new

require 'rake/testtask'
Rake::TestTask.new(:test) do |test|
  test.libs << 'lib' << 'test'
  test.pattern = 'test/**/test_*.rb'
  test.verbose = true
end

#require 'rcov/rcovtask'
#Rcov::RcovTask.new do |test|
#  test.libs << 'test'
#  test.pattern = 'test/**/test_*.rb'
#  test.verbose = true
#  test.rcov_opts << '--exclude "gems/*"'
#end

task :default => :test

require 'rdoc/task'
RDoc::Task.new do |rdoc|
  version = File.exist?('VERSION') ? File.read('VERSION') : ""

  rdoc.rdoc_dir = 'rdoc'
  rdoc.title = "dnstraverse #{version}"
  rdoc.rdoc_files.include('README*')
  rdoc.rdoc_files.include('lib/**/*.rb')
end
