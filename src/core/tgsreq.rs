use ascii::AsciiString;
use kerberust::*;
use kerberos_ccache::CCache;
use kerberust::Key;
use std::fs;

pub fn request_tgs(
    username: AsciiString,
    password: Key,
    tgtpath: Option<String>,
    service: String,
    domain: String,
    dc_ip: Ipv4Addr,
) -> Result<()> {
    let channel = kdccomm.create_channel(&user.realm)?;
    let mut parsed_ticket: Ccache = Ccache::new();

    match tgtpath {
        Some(tgtpath) => {
            let ticket = fs::read(&tgtpath).expect("Unable to read file");
            let parsed_ticket = CCache::parse(&ticket)
                .expect("Unable to parse ticket content")
                .1;
        }
        (_) => {
            let tgt_requester = TgtRequester::new(*(realm.clone()), kdc_address);

            let credential = tgt_requester
                .request(&username, Some(&password))
                .unwrap();

            let filename = format!("{}_tgt.ccache", username);
            credential.save_into_ccache_file(&filename).unwrap();
        }
    }
    
    println!("Request {} TGS for {}", username, service);
    let mut tgs = request_spn_tgs(
        (username.clone(), password.clone()),
        &service,
        CCache,
        None,
        &mut kdccomm,
    )?;

    println!("Save {} TGS for {} ", user.username.clone(), service);
    
    return Ok(());
}

pub fn request_spn_tgs(
    user: (AsciiString, Key),
    service: String,
    tgt: CCache,
    etypes: Option<Vec<i32>>,
    kdccomm: &mut KdcComm,
) -> Result<TicketCred> {
    let channel = kdccomm.create_channel(&user.realm)?;

    let mut dst_realm = user.realm.clone();
    let mut tgs = request_tgs(
        user.clone(),
        dst_realm.clone(),
        tgt,
        service.clone(),
        etypes.clone(),
        &*channel,
    )?;

  
    let channel = kdccomm.create_channel(&dst_realm)?;

    tgs = request_tgs(
        user.clone(),
        dst_realm.to_string(),
        referral_tgt,
        service.clone(),
        etypes.clone(),
        &*channel,
    )?;

    debug!(
        "{} TGS for {}\n{}",
        user,
        service.to_string(),
        ticket_cred_to_string(&tgs, 0)
    );

    return Ok(tgs);
}