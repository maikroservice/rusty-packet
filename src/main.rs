use clap::Parser;

mod kerberoasting;
use kerberoasting::kerberoasting::kerberoast;


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
    
}