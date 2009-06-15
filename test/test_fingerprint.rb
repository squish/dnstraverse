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

require 'rubygems'
gem 'dnsruby', '>=1.19'
require "test/unit"
require "dnstraverse/fingerprint"

class TestFingerprint < Test::Unit::TestCase
  def test_squishnet
    fp = DNSTraverse::Fingerprint.new
    ip = Socket.getaddrinfo("ns.squish.net", 0,
    Socket::AF_UNSPEC, Socket::SOCK_STREAM)[0][3]
    squish = fp.fingerprint(ip)
    assert_equal(squish[:product], "BIND")
  end
end