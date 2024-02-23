mod kerberoasting {
    pub fn find_spn_accounts(username: &str) {
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
    
    pub fn find_bind_dn_from_displayname(
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

}