# $Id: Fingerprint.pm,v 1.17 2005/09/05 13:33:36 jakob Exp $
#
# Copyright (c) 2003,2004,2005 Roy Arends & Jakob Schlyter.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. The name of the authors may not be used to endorse or promote products
#    derived from this software without specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
# NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
# THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

module FingerprintRules
  
  QY = [ "0,IQUERY,0,0,1,0,0,0,NOERROR,0,0,0,0",
    "0,NS_NOTIFY_OP,0,0,0,0,0,0,NOERROR,0,0,0,0",
    "0,QUERY,0,0,0,0,0,0,NOERROR,0,0,0,0",
    "0,IQUERY,0,0,0,0,1,1,NOERROR,0,0,0,0",
    "0,QUERY,0,0,0,0,0,0,NOTIMP,0,0,0,0",
    "0,IQUERY,1,0,1,1,1,1,NOERROR,0,0,0,0",
    "0,UPDATE,0,0,0,1,0,0,NOERROR,0,0,0,0",
    "0,QUERY,1,1,1,1,1,1,NOERROR,0,0,0,0", 
    "0,QUERY,0,0,0,0,0,1,NOERROR,0,0,0,0",
  ].freeze
  
  INITRULE = { :header => QY[0], :query => ". IN A" }.freeze
  
  IQ = [ "1,IQUERY,0,0,1,0,0,0,FORMERR,0,0,0,0",   # iq0
    "1,IQUERY,0,0,1,0,0,0,FORMERR,1,0,0,0",   # iq1
    "1,IQUERY,0,0,1,0,0,0,NOTIMP,0,0,0,0",    # iq2
    "1,IQUERY,0,0,1,0,0,0,NOTIMP,1,0,0,0",    # iq3
    "1,IQUERY,0,0,1,1,0,0,FORMERR,0,0,0,0",   # iq4
    "1,IQUERY,0,0,1,1,0,0,NOTIMP,0,0,0,0",    # iq5 
    "1,IQUERY,0,0,1,1,0,0,NOTIMP,1,0,0,0",    # iq6
    "1,IQUERY,1,0,1,0,0,0,NOTIMP,1,0,0,0",    # iq7
    "1,QUERY,1,0,1,0,0,0,NOTIMP,1,0,0,0",
    "1,QUERY,0,0,0,0,0,0,NOTIMP,0,0,0,0",
    "1,IQUERY,0,0,1,1,0,0,FORMERR,1,0,0,0",   # iq10
    "1,NS_NOTIFY_OP,0,0,0,0,0,0,FORMERR,1,0,0,0",
    "1,NS_NOTIFY_OP,0,0,0,0,0,0,NOTIMP,0,0,0,0",
    "1,NS_NOTIFY_OP,0,0,0,0,0,0,NOTIMP,1,0,0,0",
    "1,NS_NOTIFY_OP,0,0,0,0,0,0,NXDOMAIN,1,0,0,0",
    "1,NS_NOTIFY_OP,0,0,0,0,0,0,REFUSED,1,0,0,0",
    "1,NS_NOTIFY_OP,0,0,0,0,0,0,SERVFAIL,1,0,0,0",
    "1,NS_NOTIFY_OP,0,0,0,1,0,0,FORMERR,1,0,0,0",
    "1,NS_NOTIFY_OP,0,0,0,1,0,0,NOTIMP,0,0,0,0",
    "1,NS_NOTIFY_OP,0,0,0,1,0,0,NOTIMP,1,0,0,0",
    "1,NS_NOTIFY_OP,0,0,0,1,0,0,REFUSED,1,0,0,0", # iq20
    "1,NS_NOTIFY_OP,0,0,0,1,0,0,SERVFAIL,1,0,0,0",
    "1,NS_NOTIFY_OP,1,0,0,0,0,0,NOTIMP,1,0,0,0",
    "1,QUERY,1,0,0,0,0,0,NOTIMP,1,0,0,0",
    "1,NS_NOTIFY_OP,1,0,0,0,0,0,SERVFAIL,1,0,0,0",
    "1,IQUERY,0,0,0,0,1,1,NOTIMP,0,0,0,0",
    "1,IQUERY,0,0,0,0,0,0,NOTIMP,0,0,0,0",
    "1,IQUERY,0,0,1,1,1,1,FORMERR,0,0,0,0",
    "1,IQUERY,1,0,1,1,1,1,FORMERR,0,0,0,0",
    "1,QUERY,.,0,1,.,.,.,NOTIMP,.+,.+,.+,.+",
    "1,QUERY,.,0,1,.,.,.,.+,.+,.+,.+,.+", #iq30
    "1,QUERY,0,0,.,.,0,0,NXDOMAIN,1,0,0,0",    
    "1,QUERY,0,0,.,.,0,0,FORMERR,1,0,0,0",
    "1,UPDATE,0,0,0,0,0,0,NOTIMP,0,0,0,0",
    "1,UPDATE,0,0,0,1,0,0,NOTIMP,0,0,0,0",
    "1,QUERY,0,0,1,0,0,0,NOERROR,1,0,0,0",
    "1,QUERY,1,1,1,1,1,1,NOTIMP,1,0,0,0",
    "1,QUERY,0,0,0,0,0,0,NOERROR,1,0,.+,0",
    "1,QUERY,0,0,1,0,0,0,FORMERR,1,0,0,0",
    "1,IQUERY,0,0,1,0,1,1,NOTIMP,1,0,0,0",
    "1,IQUERY,0,0,0,1,1,1,REFUSED,1,0,0,0", #iq40
    "1,UPDATE,0,0,0,1,0,0,REFUSED,1,0,0,0",
    "1,IQUERY,0,0,0,1,1,1,FORMERR,0,0,0,0",
    "1,IQUERY,0,0,0,1,0,0,NOTIMP,0,0,0,0",
    "1,QUERY,1,0,1,0,0,0,FORMERR,1,0,0,0",
    "1,UPDATE,0,0,0,0,0,0,FORMERR,1,0,0,0",
    "1,UPDATE,0,0,0,0,0,0,FORMERR,0,0,0,0",
    "1,QUERY,0,0,1,0,0,0,FORMERR,0,0,0,0",
    "1,QUERY,0,0,1,0,0,0,SERVFAIL,1,0,0,0", #iq48
    "1,QUERY,1,0,1,0,0,0,NXDOMAIN,1,0,1,0",
    "1,QUERY,0,0,1,0,0,0,REFUSED,1,0,0,0", #iq50
    "1,QUERY,0,0,1,0,0,0,NOERROR,1,1,0,0",
    "1,IQUERY,0,0,1,0,0,0,REFUSED,0,0,0,0",
    "1,QUERY,0,0,0,0,0,0,FORMERR,0,0,0,0",
    "1,QUERY,0,0,1,1,1,0,NOERROR,1,0,1,0",
    "1,QUERY,0,0,1,1,0,0,NOERROR,1,0,1,0",
    "1,QUERY,0,0,1,0,1,0,NOERROR,.+,.+,.+,.+", 
    "1,QUERY,0,0,1,0,0,0,.+,.+,.+,.+,.+",
    "1,QUERY,1,0,1,0,0,0,NOERROR,1,1,0,0",
    "1,QUERY,0,0,1,1,0,0,SERVFAIL,1,0,0,0", 
    "1,QUERY,1,0,1,1,0,0,NOERROR,1,1,0,0", #iq60
    "1,QUERY,0,0,1,1,0,0,REFUSED,1,0,0,0",
    "1,QUERY,0,0,0,0,0,0,NOTIMP,1,0,0,0",
    "1,QUERY,1,0,1,1,0,0,NOERROR,1,0,1,0",
    "1,IQUERY,0,0,1,1,1,1,NOTIMP,0,0,0,0",
    "1,UPDATE,0,0,0,0,0,0,REFUSED,0,0,0,0",
    "1,IQUERY,0,0,0,1,1,1,NOTIMP,1,0,0,0",
    "1,IQUERY,0,0,0,1,0,0,NOTIMP,1,0,0,0",
    "1,QUERY,0,1,1,1,1,1,NOERROR,1,0,.,0",
    "1,QUERY,0,1,1,1,0,1,NOERROR,1,0,.,0",
    "1,IQUERY,0,0,1,0,0,0,REFUSED,1,0,0,0", #iq70
    "1,IQUERY,1,0,1,1,1,1,NOTIMP,1,0,0,0",
    "1,IQUERY,0,0,1,0,0,0,NOERROR,1,0,0,0",
    "1,QUERY,1,0,1,1,0,0,NOERROR,1,0,0,0",
    "1,IQUERY,1,0,1,1,0,0,NXDOMAIN,1,0,0,0",
    "1,UPDATE,0,0,0,1,0,0,FORMERR,0,0,0,0",
    "1,IQUERY,1,0,1,0,0,0,NXDOMAIN,1,0,0,0",
    "1,QUERY,0,0,1,1,0,0,FORMERR,1,0,0,0",
    "1,QUERY,0,0,0,1,0,0,SERVFAIL,1,0,0,0",
    "1,QUERY,0,0,1,1,0,0,NOERROR,1,1,0,0",
    "1,IQUERY,1,0,1,0,0,0,NOERROR,1,0,0,0", #iq80
    "1,IQUERY,1,0,1,1,0,0,NOTIMP,1,0,0,0",
    "1,QUERY,0,0,1,1,0,0,NOERROR,1,0,0,0",
    "1,QUERY,1,0,1,1,0,0,NOERROR,1,1,1,.+",
    "1,QUERY,0,0,1,1,0,0,REFUSED,0,0,0,0",
    "1,UPDATE,0,0,0,1,0,0,NOTIMP,1,0,0,0",
    "1,QUERY,1,0,0,1,0,0,NXDOMAIN,1,0,0,0",
    "1,QUERY,0,0,0,1,0,0,NOTIMP,0,0,0,0",
    "1,QUERY,0,0,0,0,0,0,REFUSED,1,0,0,0",
    "1,QUERY,1,0,1,1,0,0,NXDOMAIN,1,0,0,0",
    "1,QUERY,1,0,0,0,0,0,NOERROR,1,1,0,0", #iq90
    "1,IQUERY,1,0,1,1,0,1,NOTIMP,1,0,0,0",
    "1,QUERY,0,0,0,1,0,0,NOTIMP,1,0,0,0",
    "1,QUERY,0,0,1,0,0,1,SERVFAIL,1,0,0,0",
  ].freeze
  
  RULESET = [
  { :fingerprint => "query timed out" , :header => QY[0],  :query => "com. IN A", :ruleset => [
    { :fingerprint => "query timed out", :header => QY[7], :query => ". CH A", :ruleset => [
      { :fingerprint => "query timed out", :header => QY[6], :query => ". IN A", :ruleset => [
        { :fingerprint => IQ[38], :result => { :vendor => "Digital Lumber", :product => "Oak DNS", :version =>"" },  :qv => ":version.oak",}, 
##        { :fingerprint => "query timed out", :result => "TIMEOUT",}, 
        { :fingerprint => ".+", :state => "q0tq0tq7tq6r?", }, ]
      },
      { :fingerprint => IQ[35], :result => { :vendor => "XBILL", :product => "jnamed (dnsjava)", :version => "" }, },
      { :fingerprint => IQ[36], :result => { :vendor => "menandmice", :product => "QuickDNS", :version => ""}, }, 
      { :fingerprint => IQ[37], :result => { :vendor => "unknown", :product => "NonSequitur DNS", :version => ""}, },
      { :fingerprint => ".+", :state => "q0tq0tq7r?", }, ]  
    },
    { :fingerprint => IQ[35], :result => { :vendor => "eNom", :product => "eNom DNS", :version =>""}, },
    { :fingerprint => ".+", :state => "q0tq0r?", },]
  },
  
  { :fingerprint => IQ[0], :header => QY[1], :query=> "jjjjjjjjjjjj IN A", :ruleset => [
    { :fingerprint => IQ[12], :result => { :vendor => "ISC", :product => "BIND", :version => "8.4.1-p1" },  :qv => ":version.bind",},                         
    { :fingerprint => IQ[13], :result => { :vendor => "ISC", :product => "BIND", :version => "8 plus root server modifications"},  :qv => ":version.bind",}, 
    { :fingerprint => IQ[15], :result => { :vendor => "Cisco", :product => "CNR", :version => ""}, },
    { :fingerprint => IQ[16], :header => QY[2], :query => "hostname.bind CH TXT", :ruleset => [
      { :fingerprint => IQ[58], :result => { :vendor => "ISC", :product => "BIND", :version => "8.3.0-RC1 -- 8.4.4"},  :qv => ":version.bind",},     
      { :fingerprint => IQ[50], :result => { :vendor => "ISC", :product => "BIND", :version => "8.3.0-RC1 -- 8.4.4"},  :qv => ":version.bind",},    
      { :fingerprint => IQ[48], :result => { :vendor => "ISC", :product => "BIND", :version => "8.2.2-P3 -- 8.3.0-T2A"},  :qv => ":version.bind",},
      { :fingerprint => ".+", :state => "q0r0q1r16q2r?", },]
    },
    { :fingerprint => ".+", :state => "q0r0q1r?", },]
  },
  
  { :fingerprint => IQ[1], :header => QY[2], :query => ". IN IXFR", :ruleset => [
    { :fingerprint => IQ[31], :result => { :vendor => "Microsoft", :product => "Windows DNS", :version => "2000" }, },        
    { :fingerprint => IQ[32], :result => { :vendor => "Microsoft", :product => "Windows DNS", :version => "NT4" }, },
    { :fingerprint => IQ[50], :result => { :vendor => "Microsoft", :product => "Windows DNS", :version => "2003"}, },
    { :fingerprint => ".+", :state => "q0r1q2r?", }, ]
  },
  
  { :fingerprint => IQ[2], :header => QY[1], :ruleset => [
    { :fingerprint => IQ[11], :result => { :vendor => "ISC", :product => "BIND", :version => "9.2.3rc1 -- 9.4.0a0" }, :qv => ":version.bind",},    
    { :fingerprint => IQ[12], :header => QY[3], :ruleset => [
      { :fingerprint => IQ[25], :header => QY[6], :ruleset => [
        { :fingerprint => IQ[33], :result => { :vendor => "bboy", :product => "MyDNS", :version => "" },},        
        { :fingerprint => IQ[34], :header => QY[2],  :query  => "012345678901234567890123456789012345678901234567890123456789012.012345678901234567890123456789012345678901234567890123456789012.012345678901234567890123456789012345678901234567890123456789012.0123456789012345678901234567890123456789012345678901234567890. IN A", :ruleset => [
          { :fingerprint => IQ[47], :result => { :vendor => "NLnetLabs", :product => "NSD", :version => "1.0.3 -- 1.2.1"}, :qv => ":version.server", }, 
          { :fingerprint => IQ[48], :header => QY[2],  :query  => "hostname.bind CH TXT", :ruleset => [
            { :fingerprint => IQ[50], :result => { :vendor => "NLnetLabs", :product => "NSD", :version => "1.2.2" }, :qv => ":version.server", },
            { :fingerprint => IQ[51], :header => QY[8], :query => ". IN A", :ruleset => [
              { :fingerprint => IQ[93], :result => { :vendor => "NLnetLabs", :product => "NSD", :version => "1.2.3 -- 2.1.2" } , :qv => ":version.server",  },
              { :fingerprint => IQ[48], :result => { :vendor => "NLnetLabs", :product => "NSD", :version => "2.1.3" }, :qv => ":version.server",  }, 
              { :fingerprint => ".+", :state => "q0r2q1r12q3r25q6r34q2r48q2r51q8r?", }, ]
            },
            { :fingerprint => ".+", :state => "q0r2q1r12q3r25q6r34q2r48q2r?", }, ]
          },
          { :fingerprint => IQ[49], :header => QY[2],  :query  => "hostname.bind CH TXT", :ruleset => [
            { :fingerprint => IQ[50], :result => { :vendor => "NLnetLabs", :product => "NSD", :version => "1.2.2 [root]"} , :qv => ":version.server",  },
            { :fingerprint => IQ[51], :result => { :vendor => "NLnetLabs", :product => "NSD", :version => "1.2.3 [root]"}, :qv => ":version.server", }, 
            { :fingerprint => ".+", :state => "q0r2q1r12q3r25q6r34q2r49q2r?", }, ]
          },
          { :fingerprint => IQ[53], :result => { :vendor => "NLnetLabs", :product=>"NSD", :version => "1.0.2"}, :qv => ":version.server", },
          { :fingerprint => ".+", :state => "q0r2q1r12q3r25q6r34q2a?", },]
        },
        { :fingerprint => ".+", :state => "q0r2q1r12q3r25q6r?", },]
      },
      { :fingerprint => IQ[26], :result => { :vendor => "VeriSign", :product => "ATLAS", :version => ""},}, 
      { :fingerprint => ".+", :state => "q0r2q1r12q3r?", },] 
    },
    { :fingerprint => IQ[15],  :header => QY[6], :ruleset => [
      { :fingerprint => IQ[45], :result => { :vendor => "Nominum", :product =>"ANS", :version =>""}, :qv => ":version.bind",},
      { :fingerprint => IQ[65], :result => { :vendor => "ISC", :product => "BIND", :version => "9.2.3rc1 -- 9.4.0a0" },  :qv => ":version.bind",},
      { :fingerprint => IQ[46], :header => QY[7], :ruleset => [
        { :fingerprint => IQ[56], :result => { :vendor => "ISC", :product => "BIND", :version => "9.0.0b5 -- 9.0.1" }, :qv => ":version.bind",},
        { :fingerprint => IQ[57], :result => { :vendor => "ISC", :product => "BIND", :version => "9.1.0 -- 9.1.3" }, :qv => ":version.bind",}, 
        { :fingerprint => ".+", :state => "q0r2q1r15q6r46q7r?", }, ]
      },
      { :fingerprint => ".+", :state => "q0r2q1r15q6r?", },]
    },
    { :fingerprint => IQ[16], :header => QY[4], :ruleset => [
      { :fingerprint => IQ[29], :result => { :vendor => "ISC", :product => "BIND", :version => "9.2.0a1 -- 9.2.0rc3"}, :qv => ":version.bind",},
      { :fingerprint => IQ[30],  :header => QY[0], :query  => ". A CLASS0" , :ruleset => [
        { :fingerprint => IQ[2], :result => { :vendor=>"ISC", :product => "BIND", :version =>"9.2.0rc7 -- 9.2.2-P3"}, :qv => ":version.bind", },
        { :fingerprint => IQ[0], :result => { :vendor=>"ISC", :product => "BIND", :version =>"9.2.0rc4 -- 9.2.0rc6"}, :qv => ":version.bind", },
        { :fingerprint => ".+", :result => { :vendor => "ISC", :product => "BIND", :version =>"9.2.0rc4 -- 9.2.2-P3"}, :qv => ":version.bind", }, ]
      },
      { :fingerprint => ".+", :state => "q0r2q1r16q4r?", },]
    },
    { :fingerprint => ".+", :state => "q0r2q1r?", }, ]
  },
  
  { :fingerprint => IQ[3], :header => QY[1], :ruleset => [
    { :fingerprint => "query timed out", :header => QY[5], :ruleset => [
      { :fingerprint => IQ[3], :result => { :vendor => "sourceforge", :product =>"Dents", :version =>""}, :qv => ":version.bind", },
      { :fingerprint => IQ[81], :result => { :vendor => "Microsoft", :product => "Windows DNS", :version => "2003" },},
      { :fingerprint => IQ[91], :result => { :vendor => "Microsoft", :product => "Windows DNS", :version => "2003" },},
      { :fingerprint => ".+", :state => "q0r3q1tq5r?", }, ]
      
    },     
    { :fingerprint => IQ[14], :result => { :vendor => "UltraDNS", :product => "", :version =>"v2.7.0.2 -- 2.7.3"}, :qv => ":version.bind", }, 
    { :fingerprint => IQ[13], :header => QY[5], :ruleset => [
      { :fingerprint => IQ[39], :result => { :vendor => "pliant", :product => "DNS Server", :version =>""},},
      { :fingerprint => IQ[7], :result => { :vendor => "JHSOFT", :product => "simple DNS plus", :version =>""}, }, 
      { :fingerprint => IQ[71], :header => QY[6], :ruleset => [
        { :fingerprint => IQ[41], :result => { :vendor =>"Netnumber", :product =>"ENUM server", :version =>""}, },
        { :fingerprint => IQ[85], :result => { :vendor =>"Raiden", :product => "DNSD", :version => ""}, }, ]
      },
      { :fingerprint => ".+", :state => "q0r3q1r13q5r?", }, ]
    },
    { :fingerprint => ".+", :state => "q0r3q1r?", }, ]
  },
  
  { :fingerprint => IQ[4], :header => QY[1], :query=> "jjjjjjjjjjjj IN A", :ruleset => [
    { :fingerprint => IQ[17], :result => { :vendor => "ISC", :product => "BIND", :version =>"9.0.0b5 -- 9.0.1 [rcursion enabled]"}, :qv => ":version.bind", },
    { :fingerprint => IQ[18], :header => QY[5], :query=> ". IN A" , :ruleset => [
      { :fingerprint => IQ[27], :result => { :vendor => "ISC", :product => "BIND", :version => "4.9.3 -- 4.9.11"}, :qv => ":version.bind", },
      { :fingerprint => IQ[28], :result => { :vendor => "ISC", :product => "BIND", :version => "4.8 -- 4.8.3"}, }, 
      { :fingerprint => ".+", :state => "q0r4q1r18q5r?", }, ]
    },
    { :fingerprint => IQ[19], :result => {:vendor => "ISC", :product =>"BIND", :version => "8.2.1 [recursion enabled]"}, :qv => ":version.bind", },           
    { :fingerprint => IQ[20], :header => QY[3], :query=> ". IN A", :ruleset => [
      { :fingerprint => IQ[42], :result => {:vendor => "ISC", :product =>"BIND", :version =>"8.1-REL -- 8.2.1-T4B [recursion enabled]"}, :qv => ":version.bind", }, 
      { :fingerprint => ".+", :state => "q0r4q1r20q3r?", },]
    },
    { :fingerprint => IQ[21], :header => QY[2], :query => "hostname.bind CH TXT", :ruleset => [
      { :fingerprint => IQ[60], :result => {:vendor =>"ISC", :product => "BIND", :version => "8.3.0-RC1 -- 8.4.4 [recursion enabled]"},  :qv => ":version.bind",},
      { :fingerprint => IQ[59], :header => QY[7], :query=> ". IN A", :ruleset => [
        { :fingerprint => IQ[68], :result => {:vendor =>"ISC", :product => "BIND", :version => "8.1-REL -- 8.2.1-T4B [recursion enabled]"}, :qv => ":version.bind", },
        { :fingerprint => IQ[69], :result => {:vendor =>"ISC", :product => "BIND", :version => "8.2.2-P3 -- 8.3.0-T2A [recursion enabled]"},  :qv => ":version.bind",},
        { :fingerprint => "connection failed", :result => { :vendor =>"Runtop", :product => "dsl/cable", :version =>""},},
        { :fingerprint => ".+", :state => "q0r4q1r21q2r59q7r?", },]
      },
      
      { :fingerprint => IQ[58], :result => {:vendor => "ISC", :product =>"BIND", :version => "8.3.0-RC1 -- 8.4.4 [recursion local]"},  :qv => ":version.bind",},
      { :fingerprint => IQ[50], :result => {:vendor => "ISC", :product =>"BIND", :version => "8.3.0-RC1 -- 8.4.4 [recursion local]"},  :qv => ":version.bind",},
      { :fingerprint => IQ[61], :result => {:vendor => "ISC", :product =>"BIND", :version => "8.3.0-RC1 -- 8.4.4 [recursion local]"},  :qv => ":version.bind",},
      { :fingerprint => IQ[48], :result => {:vendor => "ISC", :product =>"BIND", :version => "8.2.2-P3 -- 8.3.0-T2A [recursion local]"},  :qv => ":version.bind",},
      { :fingerprint => ".+", :state => "q0r4q1r21q2r?", },]
    },
    { :fingerprint => ".+", :state => "q0r4q1r?", }, ]
  },
  
  { :fingerprint => IQ[5], :header => QY[1], :ruleset => [
    { :fingerprint => IQ[11], :result => { :vendor => "ISC", :product => "BIND", :version => "9.2.3rc1 -- 9.4.0a0", :option => "recursion enabled,split view" }, :qv => ":version.bind",},
    { :fingerprint => IQ[17], :result => {:vendor => "ISC", :product =>"BIND", :version => "9.2.3rc1 -- 9.4.0a0 [recursion enabled]"}, :qv => ":version.bind",},
    { :fingerprint => IQ[18], :header => QY[5], :ruleset => [
      { :fingerprint => IQ[5], :header => QY[7], :query  => ". IN A", :ruleset => [
        { :fingerprint => IQ[84], :result => {:vendor => "Nominum", :product =>"CNS", :version => ""}, :qv => ":version.bind",},
        { :fingerprint => IQ[59], :result => {:vendor => "Mikrotik", :product =>"dsl/cable", :version => ""}, },
        { :fingerprint => IQ[82], :result => {:vendor => "Mikrotik", :product =>"dsl/cable", :version => ""}, },
        { :fingerprint => ".+", :state => "q0r5q1r18q5r5q7r?", }, ]
      },
##      { :fingerprint => IQ[64], :result => "unknown, smells like old BIND 4", },
      { :fingerprint => ".+", :state => "q0r5q1r18q5r?", }, ]
    }, 
    { :fingerprint => IQ[20], :header => QY[7], :ruleset => [
      { :fingerprint => IQ[54], :result => {:vendor => "ISC", :product =>"BIND", :version => "9.0.0b5 -- 9.0.1 [recursion enabled]"}, :qv => ":version.bind",},
      { :fingerprint => IQ[55], :result => {:vendor => "ISC", :product =>"BIND", :version => "9.1.0 -- 9.1.3 [recursion enabled]"}, :qv => ":version.bind",},
      { :fingerprint => IQ[63], :result => {:vendor => "ISC", :product =>"BIND", :version => "4.9.3 -- 4.9.11 [recursion enabled]"}, :qv => ":version.bind",},
      { :fingerprint => IQ[61], :result => {:vendor => "ISC", :product =>"BIND", :version => "9.0.0b5 -- 9.1.3 [recursion local]"}, :qv => ":version.bind",},
      { :fingerprint => ".+", :state => "q0r5q1r20q7r?", }, ]
    },   
    { :fingerprint => IQ[21], :header => QY[4], :ruleset => [
      { :fingerprint => "query timed out", :result => {:vendor => "ISC", :product =>"BIND", :version => "9.2.0a1 -- 9.2.2-P3 [recursion enabled]"}, :qv => ":version.bind", },
      { :fingerprint => IQ[29], :result => {:vendor => "ISC", :product =>"BIND", :version => "9.2.0a1 -- 9.2.0rc3 [recursion enabled]"}, :qv => ":version.bind", },
      { :fingerprint => IQ[61], :header => QY[0], :query  => ". A CLASS0" , :ruleset => [
        { :fingerprint => IQ[2], :result => {:vendor => "ISC", :product =>"BIND", :version => "9.2.0rc7 -- 9.2.2-P3 [recursion local]"}, :qv => ":version.bind", },
        { :fingerprint => IQ[0], :result => {:vendor => "ISC", :product =>"BIND", :version => "9.2.0a1 -- 9.2.0rc6 [recursion local]"}, :qv => ":version.bind", },
        { :fingerprint => ".+", :result => {:vendor => "ISC", :product =>"BIND", :version => "9.2.0a1 -- 9.2.2-P3 [recursion local]"}, :qv => ":version.bind", }, ]
      },
      { :fingerprint => IQ[30], :header => QY[0], :query  => ". A CLASS0" , :ruleset => [
        { :fingerprint => IQ[2], :result => {:vendor => "ISC", :product =>"BIND", :version => "9.2.0rc7 -- 9.2.2-P3 [recursion enabled]"}, :qv => ":version.bind", },
        { :fingerprint => IQ[0], :result => {:vendor => "ISC", :product =>"BIND", :version => "9.2.0rc4 -- 9.2.0rc6 [recursion enabled]"}, :qv => ":version.bind", },
        { :fingerprint => ".+", :result => {:vendor => "ISC", :product =>"BIND", :version => "9.2.0rc4 -- 9.2.2-P3 [recursion enabled]"}, :qv => ":version.bind", }, ] 
      },
      { :fingerprint => ".+", :state => "q0r5q1r21q4r?", }, ]
    }, 
    { :fingerprint => ".+", :state => "q0r5q1r?", }, ]
  },
  
  { :fingerprint => IQ[6], :header => QY[1], :ruleset => [
    { :fingerprint => IQ[15], :result => {:vendor => "incognito", :product =>"DNS commander", :version => "v2.3.1.1 -- 4.0.5.1"}, :qv => ":version.bind",  },
    { :fingerprint => IQ[19], :header => QY[3], :ruleset => [
      { :fingerprint => IQ[66], :result => {:vendor => "vermicelli", :product =>"totd", :version => ""}, },
      { :fingerprint => IQ[67], :result => {:vendor => "JHSOFT", :product =>"simple DNS plus", :version => "[recursion enabled]"}, }, 
      { :fingerprint => ".+", :state => "q0r6q1r19q3r?", }, ]
    },
    { :fingerprint => ".+", :state => "q0r6q1r?", }, ]
  },
  
  { :fingerprint => IQ[7], :header => QY[1], :ruleset => [
    { :fingerprint => IQ[22], :result => {:vendor => "PowerDNS", :product =>"PowerDNS", :version => "2.9.4 -- 2.9.11"}, :qv => ":version.bind", },
    { :fingerprint => IQ[24], :result => {:vendor => "PowerDNS", :product =>"PowerDNS", :version => "2.8 -- 2.9.3"}, :qv => ":version.bind", },
    { :fingerprint => ".+", :state => "q0r7q1r?", }, ]
  },
  
  { :fingerprint => IQ[8], :header => QY[1], :ruleset => [
    { :fingerprint => IQ[23], :header => QY[2] , :query => ". CH A", :ruleset => [
      { :fingerprint => "query timed out", :result => { :vendor => "DJ Bernstein", :product => "TinyDNS", :version => "1.04"} ,},
      { :fingerprint => IQ[32], :result => {:vendor => "DJ Bernstein", :product => "TinyDNS", :version => "1.05"} ,}, 
      { :fingerprint => ".+", :state => "q0r8q1r23q2r?",},]
    },
    { :fingerprint => ".+", :state => "q0r8q1r?", }, ]
  },
  
  { :fingerprint => IQ[9], :header => QY[1], :ruleset => [
    { :fingerprint => IQ[9], :result => { :vendor => "Sam Trenholme", :product =>"MaraDNS", :version => ""}, :qv => "erre-con-erre-cigarro.maradns.org"}, 
    { :fingerprint => ".+", :state => "q0r9q1r?", }, ]
  },
  
  { :fingerprint => IQ[10], :result => { :vendor => "Microsoft", :product =>"?", :version => ""}, },
  { :fingerprint => IQ[26], :result => { :vendor => "Meilof Veeningen", :product =>"Posadis", :version =>""}, },
  { :fingerprint => IQ[43], :header => QY[6], :ruleset => [
    { :fingerprint => IQ[34], :result => { :vendor => "Paul Rombouts", :product =>"pdnsd", :version =>""}, },
    { :fingerprint => IQ[75], :result => { :vendor => "antirez", :product =>"Yaku-NS", :version =>""}, },
    { :fingerprint => ".+", :state => "q0r43q6r?", }, ]
  },
  
  { :fingerprint => IQ[44], :result => { :vendor =>"cpan", :product=>"Net::DNS Nameserver", :version =>""}, :qv => ":version.bind", },
  { :fingerprint => IQ[52], :result => { :vendor =>"NLnetLabs", :product=>"NSD", :version => "1.0 alpha"}, },
  { :fingerprint => IQ[55], :result => { :vendor =>"robtex", :product=>"Viking DNS module", :version=>""}, },
  { :fingerprint => IQ[59], :result => { :vendor =>"Max Feoktistov", :product=>"small HTTP server [recursion enabled]", :version =>""}, },
  { :fingerprint => IQ[60], :result => { :vendor =>"Axis", :product=>"video server", :version =>""}, },
  { :fingerprint => IQ[62], :header => QY[7], :query => "1.0.0.127.in-addr.arpa. IN PTR", :ruleset => [
    { :fingerprint => IQ[62], :result => { :vendor =>"Michael Tokarev", :product=>"rbldnsd",:version=>""}, :qv => ":version.bind", },
    { :fingerprint => IQ[79], :result => { :vendor =>"4D", :product=>"WebSTAR", :version=>""}, },
    { :fingerprint => IQ[83], :result => { :vendor =>"Netopia", :product =>"dsl/cable", :version => ""},},
    { :fingerprint => IQ[90], :result => { :vendor =>"TZO", :product=>"Tzolkin DNS",:version=>""}, },
    { :fingerprint => "query timed out", :result => { :vendor =>"Netopia", :product =>"dsl/cable", :version=>""},},
    { :fingerprint => ".+", :state => "q0r62q7r?", }, ]
  },
  { :fingerprint => IQ[70], :result => { :vendor =>"Yutaka Sato", :product=>"DeleGate DNS", :version=>""},},
  { :fingerprint => IQ[72], :result => { :vendor =>"", :product =>"sheerdns", :version=>""}, },
  { :fingerprint => IQ[73], :result => { :vendor =>"Matthew Pratt", :product=>"dproxy", :version=>""}, },
  { :fingerprint => IQ[74], :result => { :vendor =>"Brad Garcia", :product=>"dnrd",:version=>""}, },
  { :fingerprint => IQ[76], :result => { :vendor =>"Sourceforge", :product=>"JDNSS",:version=>""}, },
  { :fingerprint => IQ[77], :result => { :vendor =>"Dan Kaminsky", :product=>"nomde DNS tunnel",:version=>""}, },
  { :fingerprint => IQ[78], :result => { :vendor =>"Max Feoktistov", :product=>"small HTTP server", :version =>""}, },
  { :fingerprint => IQ[79], :result => { :vendor =>"robtex", :product=>"Viking DNS module", :version=>""}, },
  { :fingerprint => IQ[80], :result => { :vendor =>"Fasthosts", :product=>"Envisage DNS server", :version=>""}, },
  { :fingerprint => IQ[81], :result => { :vendor =>"WinGate", :product=>"Wingate DNS", :version=>""},},
  { :fingerprint => IQ[82], :result => { :vendor =>"Ascenvision", :product=>"SwiftDNS", :version=>""},},
  { :fingerprint => IQ[86], :result => { :vendor =>"Nortel Networks", :product=>"Instant Internet",:version=>""}, },
  { :fingerprint => IQ[87], :result => { :vendor =>"ATOS", :product=>"Stargate ADSL", :version=>""},},
  { :fingerprint => IQ[88], :result => { :vendor =>"3Com", :product=>"Office Connect Remote", :version=>""},},
  { :fingerprint => IQ[89], :result => { :vendor =>"Alteon", :product=>"ACEswitch", :version=>""},},
  { :fingerprint => IQ[90], :result => { :vendor =>"javaprofessionals", :product=>"javadns/jdns", :version=>""},},
  
  { :fingerprint => IQ[92], :result => { :vendor =>"Beehive", :product=>"CoDoNS",:version=>""}, },
  { :fingerprint => ".+", :state => "q0r?", }, 
  
  ].freeze
end
