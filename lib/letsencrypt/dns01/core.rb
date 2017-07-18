require 'resolv'
require 'logger'
require 'acme-client'
require 'fileutils'
require 'date'
# require 'mail'
module Letsencrypt
  module Dns01
    # Your code goes here...
  end
end

class Letsencrypt::Dns01::BIND9

    def initialize(cfg)
      @serial = Date.today.strftime('%Y%m%d00').to_i
      @core=Letsencrypt::Dns01::Core.new(cfg)
    end

    def update()
      #add token and update serial
      @core.authorize do |v|
        update_zonefile(v)
      end

      @serial
    end

    def update_zonefile(token="")
      filename=@core.zone[:zonefile]
      content=File.read(filename)
      #update serial
      content.sub!(/^\s+(\d+)\s*\;\s*serial$/i) do |m|
          @serial=[$1.to_i+1,@serial].max
          $&.sub(/\d+/,@serial.to_s)
      end
      #delete old token
      content.sub!(/^\; token area$.*\z/im) do |m|
          "; token area\n"
      end
      #add new token
      content+=token

      #write zonefile
      File.write(filename,content)

      #reload name server
      @core.zone[:command].each{|c| system(c)} if @core.zone[:command]
    end
end


class Letsencrypt::Dns01::Core
  Token = Struct.new(:domain, :challenge)
  attr_reader :zone, :log

  # initialize login to ACME server.
  # And it creates an authrization key file, if necessary.
  def initialize(zone={})
    @zone = normalization(zone)
    @client = set_client()
    @log = Logger.new(@zone[:logfile], 5, 1024000)
  end
  
  # authorize gets the authrization/verification token from the ACME server according to the domain list.
  # returns a number of verification.
  def authorize
    if expire?
      @log.info "start update"
      ret=@zone[:domain].reduce(0) do |sum,domain|
        @log.info "authorize #{sum},#{domain}"
        
        #get challenge token
        authorization = @client.authorize(domain: domain)
        challenge = authorization.dns01
        
        #update DNS record
        yield(%(#{challenge.record_name}.#{domain}. IN #{challenge.record_type} "#{challenge.record_content}"\n))

        #check DNS record
        dns=Resolv::DNS.new(:nameserver => @zone[:nameserver])
        cname="#{challenge.record_name}.#{domain}"
        ctxt=challenge.record_content
        @log.info  "token #{sum},#{ctxt}"
        begin
          sleep 10
          ret=dns.getresources(cname, Resolv::DNS::Resource::IN::TXT)
        end until ret.size > 0 && ctxt==ret[0].data

        #verify token
        challenge.request_verification
        sleep 5 while challenge.verify_status == "pending"
        sum+=1 if challenge.verify_status=="valid"
        # sum+=1 if t.challenge.verify_status=="invalid"
        @log.info "verified! #{sum},#{domain}"
        sum
      end

      #delete DNS record
      yield("")

      #cartificate
      if ret==@zone[:domain].size
        serial=Time.now.strftime("%Y%m%d%H%M%S")
        @log.info "update_cert #{serial}"
        update_cert(serial)
      end

      @log.info "complete update."
    else
      @log.info "skip update"
    end
    @log.close
  end
  
  # private

  def normalization(zone)
    zone[:endpoint]||="https://acme-staging.api.letsencrypt.org"
    zone[:mail]||="root@example.com"
    
    zone[:margin_days ]||=30
    zone[:warning_days]||=7

    domains =zone[:domains ]||zone[:domain ]
    zone[:domain ]=domains
    zone[:domain ]=[domains ] unless domains.instance_of?(Array)
    commands=zone[:commands]||zone[:command]||[]
    zone[:command]=commands
    zone[:command]=[commands] unless commands.instance_of?(Array)

    zone[:certdir]||=File.expand_path(File.dirname($0))
    zone[:certname]||={}
    zone[:certname][:privkey  ]||="privkey.pem"
    zone[:certname][:cert     ]||="cert.pem"
    zone[:certname][:chain    ]||="chain.pem"
    zone[:certname][:fullchain]||="fullchain.pem"

    zone[:logfile]||=STDOUT

    zone
  end

  def set_client
    filename=@zone[:authkey]
    if File.exist?(filename)
      key = OpenSSL::PKey::RSA.new(File.read(filename))
      return Acme::Client.new(private_key: key, endpoint: @zone[:endpoint])
    end
    key = OpenSSL::PKey::RSA.new(4096)
    cli = Acme::Client.new(private_key: key, endpoint: @zone[:endpoint])
    registration = cli.register(contact: "mailto:#{@zone[:mail]}")
    registration.agree_terms
    FileUtils.mkdir_p(File.dirname(filename))
    File.write(filename, key.to_pem)
    File.chmod(0400, filename)
    cli
  end

  # update_cert updates/create some certification files under serial dir.
  def update_cert(serial)
    rcsr={names: @zone[:domain]}
    rcsr[:common_name]=@zone[:domain][0] if @zone[:domain].size > 1
    csr = Acme::Client::CertificateRequest.new(rcsr)
    certificate = @client.new_certificate(csr)

    cdir=@zone[:certdir]+"/current"
    rdir=@zone[:certdir]+"/#{serial}/"

    FileUtils.mkdir_p(rdir)

    File.write(rdir+@zone[:certname][:privkey  ], certificate.request.private_key.to_pem)
    File.write(rdir+@zone[:certname][:cert     ], certificate.to_pem)
    File.write(rdir+@zone[:certname][:chain    ], certificate.chain_to_pem)
    File.write(rdir+@zone[:certname][:fullchain], certificate.fullchain_to_pem)
    
    FileUtils.rm(cdir,{force: true})
    FileUtils.ln_s(rdir.chop,cdir,{force: true})
  end
  
  # expire? check rest days by the current public key .
  # return true if no file or file is expired.
  def expire?
    fname=@zone[:certdir]+"/current/"+@zone[:certname][:cert]
    return true unless File.exist?(fname)
    
    cert = OpenSSL::X509::Certificate.new(File.read(fname))
    rest = cert.not_after - Time.now
    return false if rest > (@zone[:margin_days]*24*60*60)
    return true
  end
end

if $0 == __FILE__
  Letsencrypt::Dns01::BIND9.new({
    name: 'example.com',
    zonefile: 'spec/data/example.com.zone',
    nameserver: [ '203.0.113.0' ],
    domains: [
      'example.com',
      'www.example.com' 
    ],
    authkey: 'spec/data/key/example.com.pem',
    certdir: 'spec/data/example.com',
    logfile: 'spec/data/letsencrypt_example.com.log',
    commands: [
       #'service nsd restart',
       #'nginx -s reload',
    ],
    endpoint: 'https://acme-staging.api.letsencrypt.org',
    mail: 'hogehoge@hotmail.com',
  }).update()
end
__END__
