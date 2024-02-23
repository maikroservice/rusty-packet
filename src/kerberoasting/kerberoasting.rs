use kerbeiros::*;
use kerberos_ccache::CCache;
use ldap3::LdapResult;
use ldap3::SearchEntry;
use ldap3::SearchResult;
use ldap3::{LdapConn, Scope};
use std::fs;
use std::net::*;
use std::convert;
use ascii::AsciiString;

fn find_spn_accounts(username: &str) {
        //username: &str, password: &str, dc_ip: Option<String>, domain: Option<String>, use_ssl: bool) {
        let ldap_host = dc_ip.unwrap();
        let ldap_port: u16 = match use_ssl {
            true => 636,
            false => 389,
            _ => 389,
        };
        let ldap_pass = password;
        

        ldapcon.simple_bind(&bind_dn, "Password123!").unwrap();
        //"CN=maik ro,CN=Users,DC=snackempire,DC=home"
        let filter = "(&(objectClass=user)(servicePrincipalName=*)(!(objectCategory=computer))(!(cn=krbtgt)))";
        //let filter = format!("(&(objectClass=user)(displayName={}))", displayname);

        //let filter = "(objectclass=user)";
        println!("filter: {}", filter);
        let res = ldapcon
            .search(
                "DC=snackempire,DC=home",
                Scope::Subtree,
                &filter[..],
                vec!["dn"],
            )
            .unwrap();

        let (re, _ldapresult) = res.success().unwrap();

        for i in re {
            println!("{:#?}", SearchEntry::construct(i).dn);
        }
    }
    
fn find_bind_dn_from_displayname(
        displayname: &str,
        domain: &str,
        auth_username: &str,
        auth_password: &str,
        ldap_ip: &str,
        ldap_port: &str,
        ldap_host: Option<&str>,
        ) {
            let domain_dn = convert_domain_to_dn(domain);
            let ldap = LdapConn::new(format!("ldap://{ldap_ip}:{ldap_port}").as_str());
        
            let mut ldapcon = match ldap {
                Ok(l) => l,
                Err(r) => panic!("{}", r),
            };
            // first we try anonymous binding without credentials 
            match ldapcon.simple_bind("", "") {
                Ok(_) => {
                    println!("Anonymous bind successful");
                }
                Err(err) => {
                    println!("Anonymous bind failed, attempting with credentials");
        
                    // ok, anonymous binding was a mistake, lets try the authenticated version of it
                    let bind_result = ldapcon.simple_bind(auth_password, auth_password);
        
                    match bind_result {
                        Ok(_) => {
                            println!("Bind with credentials successful");
                        }
                        Err(err) => {
                            println!("Bind with credentials failed: {}", err);
                        }
                    }
                }
        }
        
        ldapcon.simple_bind(auth_username, auth_password).unwrap();
        
        let filter = format!("(&(objectClass=user)(displayName={}))", displayname);
        println!("filter: {}", filter);
        let res = ldapcon
            .search(
                &domain_dn,
                Scope::Subtree,
                &filter[..],
                vec!["dn"],
            )
            .unwrap();
        let (re, _ldapresult) = res.success().unwrap();
        
        println!("{:?}",SearchEntry::construct(re[0].clone()).dn);
        
        }
        
fn convert_domain_to_dn(domain: &str) -> String {
        let parts = domain.split(".").map(|part| format!("dc={part}")).collect::<Vec<_>>();
        parts.join(",")
    }

pub fn kerberoast(username: &str, password: &str, domain: &str) -> &str {
    return "HAHAHAH";
}


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

