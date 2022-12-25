
mod dumper;

use crate::dumper::Dumper;

use clap::Parser;
/// Simple program to greet a person
/// 
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
//    /// Package name to dump
//    #[arg(short, long, default_value = "")]
//    name: String,

   /// pid of the process to dump
   #[arg(short, long)]
   pid: i32,

    /// Output path
    #[arg(short, long, default_value = "/data/local/tmp/panda")]
    out_path: String,
}

fn main() {
    println!("panda-dex-dumper");

    // Parse command line arguments
    let args = Args::parse();

    let mut dumper = Dumper::new(args.pid);
    
    std::fs::create_dir_all(&args.out_path).expect("Failed to create output directory");

    println!("Attaching to process {}...", args.pid);
    println!("Output path: {}", args.out_path);

    dumper.attach_process();
    dumper.search_dex(&args.out_path);
    dumper.detach_process();

    println!("Done. Hava a nice day!");
}
