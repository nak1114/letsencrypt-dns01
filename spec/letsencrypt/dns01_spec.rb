require "spec_helper"

describe Letsencrypt::Dns01 do
  let(:cfg){
    {
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
    }
  }

  let(:cfg_not_expire){
    cfg.update({margin_days: 5})
  }

  it "has a version number" do
    expect(Letsencrypt::Dns01::VERSION).not_to be nil
  end
  
  def dummy_write_zonefile(token="")
    p token
  end
  def get_dummy_pems(days=15)
    name = "/C=US/ST=SomeState/L=AnyLocate/O=FooOrg/OU=Example/CN=example.com"
    ca   = OpenSSL::X509::Name.parse(name)
    key = OpenSSL::PKey::RSA.new(1024)
    crt = OpenSSL::X509::Certificate.new
    crt.version = 2
    crt.serial  = 1
    crt.subject = ca
    crt.issuer = ca
    crt.public_key = key.public_key
    crt.not_before = Time.now
    crt.not_after  = Time.now + days * 24 * 60 * 60
    crt.sign key, OpenSSL::Digest::SHA1.new
    [crt.to_pem,key.to_pem]
  end

  describe Letsencrypt::Dns01::BIND9 do
    before do
      obj  = double('Challenges',{
        record_name: '_acme-challenge',
        record_type: 'TXT',
        record_content: "1234567890",
        request_verification: true,
        verify_status: "valid"})

      dns=double('DNS',{data: "1234567890"})
      pems=get_dummy_pems()
      cert = double('Cert',{to_pem: pems[0],chain_to_pem: "chain_to_pem",fullchain_to_pem: "fullchain_to_pem"})
      allow(cert).to receive_message_chain(:request,:private_key,:to_pem).and_return(pems[1])

      cli  = double('Client',{new_certificate: cert})
      allow(cli).to receive_message_chain(:authorize,:dns01).and_return(obj)
      allow(cli).to receive_message_chain(:register,:agree_terms).and_return(true)

      allow(Acme::Client).to receive(:new).and_return(cli)
      allow(FileUtils   ).to receive(:ln_s).and_return("2017020106")
      allow(Resolv::DNS ).to receive_message_chain(:new,:getresources).and_return([dns])
    end

    let(:hoge){Letsencrypt::Dns01::BIND9.new(cfg)}
    let(:bind_not_expire){Letsencrypt::Dns01::BIND9.new(cfg_not_expire)}
    let(:fuga){Letsencrypt::Dns01::Core.new(cfg)}
    

    it "create new then return hoge" do
      expect(hoge).to be_a_kind_of(Letsencrypt::Dns01::BIND9)
    end

    it "#update" do
      fuga.update_cert("123")
      FileUtils.cp_r('spec/data/example.com/123/','spec/data/example.com/current')
      seri=hoge.instance_variable_get(:@serial)
      expect(hoge.update).to eq seri+2
    end

    it "#update (not_expire)" do
      fuga.update_cert("123")
      FileUtils.cp_r('spec/data/example.com/123/','spec/data/example.com/current')
      seri=bind_not_expire.instance_variable_get(:@serial)
      expect(bind_not_expire.update).to eq seri
    end

  end
  describe Letsencrypt::Dns01::Core do
  end
end
