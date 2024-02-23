use ascii::AsciiString;
use clap::Parser;
use kerbeiros::*;
use kerberos_ccache::CCache;
use ldap3::LdapResult;
use ldap3::SearchEntry;
use ldap3::SearchResult;
use ldap3::{LdapConn, Scope};
use std::convert;
use std::fs;
use std::net::*;
use std::path::PathBuf;
use std::vec::Vec;

#[derive(Parser)]
struct Cli {
    username: String,
    password: String,
    domain: String,
    kdc_ip: String,
}
fn main() {
    let args = Cli::parse();

    let username = AsciiString::from_ascii(args.username).unwrap();
    let user_password = Key::Password(args.password.to_string());
    let realm = AsciiString::from_ascii(args.domain); //AsciiString::from_ascii("SNACKEMPIRE.HOME").unwrap();

    let kdc_ip = args.kdc_ip;

    let kdc_address = Some(IpAddr::V4(kdc_ip.parse::<Ipv4Addr>().unwrap())); // Ipv4Addr::new(kdc_ip.parse()::Ipv4Addr)() //dc_ip[0], dc_ip[1], dc_ip[2], dc_ip[3])));

    // request TGT
    let tgt_requester = TgtRequester::new(realm.unwrap(), kdc_address.unwrap());

    let credential = tgt_requester
        .request(&username, Some(&user_password))
        .unwrap();

    let filename = format!("{}_tgt.ccache", username);
    credential.save_into_ccache_file(&filename).unwrap();

    // load ticket from disk
    let ticket = fs::read(&format!("./{}_tgt.ccache", username)).expect("Unable to read file");

    let _parsed_ticket = CCache::parse(&ticket)
        .expect("Unable to parse ticket content")
        .1;

    println!("ticket saved and loaded");
/*
    

    //find_spn_accounts(&username.as_str());*/
    find_bind_dn_from_displayname("maikroservice", "snackempire.home", "maikroservice", "Password123!", "192.168.0.8", "389", Some("j"))
}