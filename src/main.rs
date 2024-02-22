use ascii::AsciiString;
use clap::Parser;
use kerbeiros::*;
use kerberos_ccache::CCache;
use std::fs;
use std::net::*;
use std::path::PathBuf;
use std::vec::Vec;

#[derive(Parser)]
struct Cli {
    username: String,
    password: String,
    domain: String,
    //output_file_name: Option<String>,
    kdc_ip: String,
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
                   
    let kdc_address = Some(IpAddr::V4(Ipv4Addr::new(dc_ip[0], dc_ip[1], dc_ip[2], dc_ip[3])));

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
}
