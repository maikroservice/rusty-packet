use kerbeiros::*;
use ascii::AsciiString;
use std::net::*;

use kerberos_ccache::CCache;
use std::fs;

fn main() {
    let realm = AsciiString::from_ascii("DOMAIN.COM").unwrap();
    let kdc_address = IpAddr::V4(Ipv4Addr::new(192,168,0,8));
    let username = AsciiString::from_ascii("username").unwrap();
    let user_key = Key::Password("Password123!".to_string());

    // request TGT
    let tgt_requester = TgtRequester::new(realm, kdc_address);

    let credential = tgt_requester.request(&username, Some(&user_key)).unwrap();

    credential.save_into_ccache_file("maikroservice_tgt.ccache").unwrap();

    // load ticket from disk
    let ticket = fs::read("./maikroservice_tgt.ccache").expect("Unable to read file");
    
    let _parsed_ticket = CCache::parse(&ticket).expect("Unable to parse ticket content").1;

    println!("ticket saved and loaded");
}
