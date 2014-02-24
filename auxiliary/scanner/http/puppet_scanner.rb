##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/ZeroDayLab/metasploit-modules
# Author: Jerry Wozniak
# Email: jwozniak /at/ zerodaylab /dot/ com
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::WmapScanServer
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'           => "Puppetmaster Version Scanner",
      'Description'    => %q{
        This module attempts identify and fingerprint Puppetmaster
        instalations.
      },
      'License'        => MSF_LICENSE,
      'Author'         => [ 'Jerry Wozniak' ],
      'DefaultOptions' => { 'SSL' => true }
    )
    register_options( [ Opt::RPORT(8140) ], self.class )
    deregister_options('VHOST')
  end


  def fingerpring(res)

        http_fingerprint({ :response => res })
        tserver = res.headers['Server']
  end

  def run_host(target_host)
    begin
      res = send_request_raw({
        'uri'          => 'production/certificate/ca'),
        'method'       => 'GET'
        'headers' =>
          {
            'Accept' => 's'
          }
      }, 10)

      if res and res.code.to_i == 200 and res.body.to_s.match(/^-+BEGIN CERTIFICATE-+/)
        report_note(
          {
            :host   => target_host,
            :proto  => 'tcp',
            :sname =>  'https',
            :port   => rport,
            :type   => wdtype,
            :data   => datastore['PATH']
          })
      end
    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
    rescue ::Timeout::Error, ::Errno::EPIPE
    end
  end
end

