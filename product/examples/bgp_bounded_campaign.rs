#[path = "../tests/support/bgp_profile_campaign.rs"]
mod campaign;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 6 {
        eprintln!("usage: bgp_bounded_campaign SEED ITERATIONS INPUT_BYTES RETAINED_BYTES SECONDS SCRATCH_PARENT (suggested seed {})",campaign::DEFAULT_SEED);
        std::process::exit(2);
    }
    let number = |index: usize| args[index].parse::<u64>().expect("unsigned decimal budget");
    let r = campaign::run(
        number(0),
        number(1),
        usize::try_from(number(2)).unwrap(),
        usize::try_from(number(3)).unwrap(),
        number(4),
        std::path::Path::new(&args[5]),
    );
    println!("bounded-synthetic seed={} requested={} completed={} wire_negative_cases={} disk_peak_bytes={} elapsed_ms={} input_cap={} retained_cap={} time_cap_seconds={} sustained_fuzz=false corpus=false scale=false normative_qualified=false",
        args[0],args[1],r.iterations,r.negative_wire_cases,r.disk_peak,r.elapsed_ms,args[2],args[3],args[4]);
}
