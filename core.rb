Dir.chdir(File.expand_path(File.dirname(__FILE__))) do
  require 'bundler'
  Bundler.require
end

require 'yaml'
require 'resolv'
require 'logger'
require 'fileutils'
require 'date'
# require 'mail'
module Letsencrypt
  module Dns01
    # Your code goes here...
  end
end

class Letsencrypt::Dns01::BIND9

  attr_reader :core, :serial

  def initialize(cfg)
    @serial = Date.today.strftime('%Y%m%d00').to_i
    @core=Letsencrypt::Dns01::Core.new(cfg)
  end

  def update()
    #add token and update serial
    @core.authorize do |v|
      update_zonefile(v)
    end
  end

  def update_zonefile(token=nil)
    token_str=""
    if token
      domain=token.domain.sub(/^\*\./,"")
      token_str=%(#{token.challenge.record_name}.#{domain}. IN #{token.challenge.record_type} "#{token.challenge.record_content}"\n)
    end
    filename=@core.zone["zonefile"]
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
    content+=token_str

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
    isExpire=expire?
    if isExpire
      @log.info "start update"
      order = @client.new_order(identifiers: @zone[:domain])
      ret = order.authorizations.zip(@zone[:domain]).reduce(0) do |sum,z|
        authorization=z[0]
        domain=z[1]
        @log.info "authorize #{sum},#{domain}"

        #get challenge token
        challenge = authorization.dns
        
        #update DNS record
        yield(Token.new(domain,challenge))

        #check DNS record
        dns=Resolv::DNS.new(:nameserver => @zone[:nameserver])
        cname="#{challenge.record_name}.#{domain.sub(/^\*\./,"")}"
        ctxt=challenge.record_content
        @log.info  "token #{sum},#{ctxt}"
        begin
          sleep 5
          ret=dns.getresources(cname, Resolv::DNS::Resource::IN::TXT)
        end until ret.size > 0 && ctxt==ret[0].data

        #verify token
        challenge.request_validation
        while challenge.status == 'pending'
          sleep(2)
          challenge.reload
        end
        sum+=1 if challenge.status=="valid"
        # sum+=1 if challenge.status=="invalid"
        @log.info "verified! #{sum},#{z[1]}"
        sum
      end

      #delete DNS record
      yield()

      #cartificate
      if ret==@zone[:domain].size
        serial=Time.now.strftime("%Y%m%d%H%M%S")
        @log.info "update_cert #{serial}"
        update_cert(serial,order)
      end

      @log.info "complete update."
    else
      @log.info "skip update"
    end
    @log.close
    isExpire
  end
  
  # private

  def normalization(zone)
    zone[:endpoint]=zone["endpoint"]||"https://acme-staging.api.letsencrypt.org"
    zone[:mail]    =zone["mail"]||"root@example.com"
    
    zone[:margin_days ]=zone["margin_days" ]||30
    zone[:warning_days]=zone["warning_days"]||7

    domains =zone["domains"]||zone["domain"]
    zone[:domain ]=domains
    zone[:domain ]=[domains ] unless domains.instance_of?(Array)
    commands=zone["commands"]||zone["command"]||[]
    zone[:command]=commands
    zone[:command]=[commands] unless commands.instance_of?(Array)

    zone[:certdir]=zone["certdir"]||File.expand_path(File.dirname($0))
    zone[:certname]=zone["certname"]||{}
    zone[:certname][:privkey  ]=zone[:certname]["privkey"  ]||"privkey.pem"
    zone[:certname][:cert     ]=zone[:certname]["cert"     ]||"cert.pem"
    zone[:certname][:chain    ]=zone[:certname]["chain"    ]||"chain.pem"
    zone[:certname][:fullchain]=zone[:certname]["fullchain"]||"fullchain.pem"

    zone[:logfile]=zone["logfile"]||STDOUT

    nameserver=zone["nameserver"]||"8.8.8.8"
    zone[:nameserver]=nameserver
    zone[:nameserver]=[nameserver] unless nameserver.instance_of?(Array)

    zone[:authkey]=zone["authkey"]

    zone
  end

  def set_client
    filename=@zone[:authkey]
    if File.exist?(filename)
      key = OpenSSL::PKey::RSA.new(File.read(filename))
      kid = File.read(filename+".kid")
      return Acme::Client.new(private_key: key, directory: @zone[:endpoint]+'/directory', kid: kid)
    end
    key = OpenSSL::PKey::RSA.new(4096)
    cli = Acme::Client.new(private_key: key, directory: @zone[:endpoint]+'/directory')
    account = cli.new_account(contact: "mailto:#{@zone[:mail]}", terms_of_service_agreed: true)

    FileUtils.mkdir_p(File.dirname(filename))
    File.write(filename, key.to_pem)
    File.chmod(0400, filename)
    File.write(filename+".kid", account.kid)
    File.chmod(0400, filename+".kid")
    cli
  end

  def get_key_path(serial,k) rdir=@zone[:certdir]+"/#{serial}/"+@zone[:certname][k]; end

  # update_cert updates/create some certification files under serial dir.
  def update_cert(serial,order)
    rcsr={names: @zone[:domain]}
    rcsr[:common_name]=@zone[:domain][0] if @zone[:domain].size > 1
    rcsr[:private_key]=OpenSSL::PKey::RSA.new(2048)
    csr = Acme::Client::CertificateRequest.new(rcsr)
    order.finalize(csr: csr)
    sleep(1) while order.status == 'processing'

    cdir=@zone[:certdir]+"/current"
    rdir=@zone[:certdir]+"/#{serial}/"

    FileUtils.mkdir_p(rdir)

    File.write(rdir+@zone[:certname][:privkey  ], rcsr[:private_key].to_pem)
    File.write(rdir+@zone[:certname][:fullchain], order.certificate)
    
    FileUtils.rm(cdir,{force: true})
    FileUtils.ln_s("#{serial}/",cdir,{force: true})
  end
  
  # expire? check rest days by the current public key .
  # return true if no file or file is expired.
  def expire?
    fname=@zone[:certdir]+"/current/"+@zone[:certname][:fullchain]
    return true unless File.exist?(fname)
    
    cert = OpenSSL::X509::Certificate.new(File.read(fname))
    rest = cert.not_after - Time.now
    return false if rest > (@zone[:margin_days]*24*60*60)
    return true
  end
  
  # revoke cert file.
  # return true if success.
  def revoke(serial="current")
    cdir = @zone[:certdir]+"/#{serial}/"
    str = File.read(cdir+@zone[:certname][:fullchain])
    @client.revoke(certificate: str)
  end
end

if $0 == __FILE__
  Dir.chdir(File.expand_path(File.dirname(__FILE__))) do
    Letsencrypt::Dns01::BIND9.new(YAML.load_file("example.com.yml")).update()
  end
end
__END__
endpoint: 'https://acme-v02.api.letsencrypt.org',
endpoint: 'https://acme-staging-v02.api.letsencrypt.org',
le=Letsencrypt::Dns01::BIND9.new(YAML.load_file("example.com.yml"))
