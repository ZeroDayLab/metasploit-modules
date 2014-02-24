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

  # Starting from version 3.3.1-rc3 Puppet intruduced a custom HTTP
  # response header containing the puppet version. It is used
  # to control yaml backward compatibility mode but also allows
  # version fingerprinting.
  # See:
  # https://github.com/puppetlabs/puppet/commit/70a18ef4d3b1dc9c52c04356bf77b55
  def fingerprint(res)
      version = "Puppetmaster"
      puppet_ver = "< 3.3.1-rc3"
      http_fingerprint({ :response => res })

      data = res.headers['X-Puppet-Version']
      if data
        version << " #{data}"
      else
        version << " #{puppet_ver}"
      end

      data = res.headers['Server']
      version << " running on #{data}" if data
      return version
  end

  # Making a request for the CA Certificate of the puppetmaster doesn’t
  # require you to be authenticated with your own signed SSL Certificates,
  # since that’s something you would need before you authenticate.
  # The puppetmaster server detectection is based on the response to the
  # below request and presence of the CA cert.
  def run_host(target_host)
    begin
      target_uri = '/production/certificate/ca'
      res = send_request_raw({
        'uri'          => target_uri,
        'method'       => 'GET',
        'headers' =>
          {
            'Accept' => 's'
          }
      }, 10)

      if res and res.code == 200 and res.body.match(/^-+BEGIN CERTIFICATE-+/)
        version = fingerprint(res)
        print_good("#{target_host} - #{version}")
        report_note(
          {
            :host   => target_host,
            :proto  => 'tcp',
            :sname  => 'Puppetmaster',
            :port   => rport,
            :type   => 'Info',
            :data   => version,
          })
      end
      rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
      rescue ::Timeout::Error, ::Errno::EPIPE
    end
  end
end

