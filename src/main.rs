use ascii::AsciiString;
use clap::Parser;
use kerbeiros::*;
use kerberos_ccache::CCache;
use ldap3::SearchEntry;
use ldap3::SearchResult;
use std::fs;
use std::net::*;
use std::path::PathBuf;
use std::vec::Vec;
use ldap3::{LdapConn, Scope};

#[derive(Parser)]
struct Cli {
    username: String,
    password: String,
    domain: String,
    kdc_ip: String,
    //output_file_name: Option<String>,
    // dc_fqdn: Option<String>,
}
/*
impl Cli {
    fn new(
        username: String,
        password: String,
        domain: Option<String>,
        output_file_name: Option<String>,
        kdc_ip: Option<String>,
        dc_fqdn: Option<String>,
    ) -> Self {
         
         let dc_ip: Vec<u8> = kdc_ip
                    .unwrap()
                    .split('.')
                    .map(|octet_str: &str| octet_str.parse().unwrap()).collect();
                
        
        
            username: AsciiString::from_ascii(username).unwrap(),
            password,
            domain: Some(domain.unwrap().to_ascii_uppercase()),
            output_file_name: Some(PathBuf::from(&output_file_name.unwrap())),
            kdc_ip: Some(IpAddr::V4(Ipv4Addr::new(dc_ip[0], dc_ip[1], dc_ip[2], dc_ip[3]))),
            dc_fqdn: ,
        }
    //}
//}
*/
fn main() {
    let args = Cli::parse();
   
    let username = AsciiString::from_ascii(args.username).unwrap();
    let user_password = Key::Password(args.password.to_string());
    let realm = AsciiString::from_ascii(args.domain); //AsciiString::from_ascii("SNACKEMPIRE.HOME").unwrap();
    
    let kdc_ip = args.kdc_ip;
    let dc_ip: Vec<u8> = kdc_ip
                    .split('.')
                    .map(|octet_str: &str| octet_str.parse().unwrap()).collect();     
                   
    let kdc_address = Some(IpAddr::V4(kdc_ip.parse::<Ipv4Addr>().unwrap()));// Ipv4Addr::new(kdc_ip.parse()::Ipv4Addr)() //dc_ip[0], dc_ip[1], dc_ip[2], dc_ip[3])));

    // request TGT
    let tgt_requester = TgtRequester::new(realm.unwrap(), kdc_address.unwrap());

    let credential = tgt_requester.request(&username, Some(&user_password)).unwrap();

    let filename = format!("{}_tgt.ccache", username);
    credential.save_into_ccache_file(&filename).unwrap();

    // load ticket from disk
    let ticket = fs::read(&format!("./{}_tgt.ccache", username)).expect("Unable to read file");

    let _parsed_ticket = CCache::parse(&ticket)
        .expect("Unable to parse ticket content")
        .1;

    println!("ticket saved and loaded");

    fn find_spn_accounts(username: &str) {//username: &str, password: &str, dc_ip: Option<String>, domain: Option<String>, use_ssl: bool) {
        /*let ldap_host = dc_ip.unwrap();
        let ldap_port: u16 = match use_ssl {
            true => 636,
            false => 389,
            _ => 389,
        };
        let ldap_pass = password;
        */
        let ldap =LdapConn::new("ldap://192.168.0.8:389");

        let mut ldapcon = match ldap{
         Ok(l) => l,
         Err(r) => panic!("{}",r)
        };
        
        let displayname =  username;
        // can we do this without binding?
        ldapcon.simple_bind("", "").unwrap();

        let filter = format!("(&(objectClass=user)(displayName={}))", displayname);
        println!("filter: {}",filter);   
        let res = ldapcon.search("DC=snackempire,DC=home",Scope::Subtree,&filter[..],vec!["dn"]).unwrap();     
        let (re, _ldapresult) = res.success().unwrap();
        let mut bind_dn: String = String::new();
        for i in re { 
            bind_dn = SearchEntry::construct(i).dn;
           }

        ldapcon.simple_bind(&bind_dn, "Password123!").unwrap();
     //"CN=maik ro,CN=Users,DC=snackempire,DC=home"
        let filter = "(&(objectClass=user)(servicePrincipalName=*)(!(objectCategory=computer))(!(cn=krbtgt)))";
        //let filter = format!("(&(objectClass=user)(displayName={}))", displayname);


        //let filter = "(objectclass=user)";
        println!("filter: {}",filter);
        let res = ldapcon.search("DC=snackempire,DC=home",Scope::Subtree,&filter[..],vec!["dn"]).unwrap();
     
        let (re, _ldapresult) = res.success().unwrap();
     
        for i in re{
         println!("{:#?}",SearchEntry::construct(i).dn);
        }
    }

    find_spn_accounts(&username.as_str());
}
