use clap::Parser;

mod kerberoasting;
use kerberoasting::kerberoasting::kerberoast;

use std::fs;
use kerberos_ccache::CCache;
use std::net::{IpAddr, Ipv4Addr};
use ascii::AsciiString;
use kerberust::*;
//mod core;


#[derive(Parser)]
struct Cli {
    username: String,
    password: String,
    domain: String,
    kdc_ip: String,
}
fn main() {
    let args = Cli::parse();
    
    kerberoast(&args.username, &args.password, &args.domain, &args.kdc_ip);

    //&args.username, &args.password, &args.domain, &args.kdc_ip
    let service = "CN=snackservice,CN=Users,DC=snackempire,DC=home";

    // load tgt for user
    // load ticket from disk
    let ticket = fs::read(&format!("./{}_tgt.ccache", &args.username)).expect("Unable to read file");

    let _parsed_ticket = CCache::parse(&ticket)
        .expect("Unable to parse ticket content")
        .1;

    println!("TGT saved and loaded");

    let tgs = request_tgs(args.username.as_str(), args.password.as_str(), service, args.domain.as_str(), args.kdc_ip.as_str());
    
}

fn request_tgs(username: &str, password: &str, service: &str, domain: &str, dc_ip: &str) {
    let username = AsciiString::from_ascii(username).unwrap();
    let user_password = Key::Password(password.to_string());
    // realm needs to be a box because otherwise we cannot use it twice (asciistring does not implement copy/clone 😅)
    let realm = Box::new(AsciiString::from_ascii(domain).unwrap()); //AsciiString::from_ascii("SNACKEMPIRE.HOME").unwrap();

    let kdc_address = Some(IpAddr::V4(dc_ip.parse::<Ipv4Addr>().unwrap())).unwrap(); // Ipv4Addr::new(kdc_ip.parse()::Ipv4Addr)() //dc_ip[0], dc_ip[1], dc_ip[2], dc_ip[3])));


}