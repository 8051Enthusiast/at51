pub mod base;
mod instr;
pub mod kinit;
pub mod libfind;
pub mod stat;

use clap::{App, Arg, SubCommand};
use std::convert::TryInto;
use std::fs::File;
use std::io::Read;
use std::process;

fn main() {
    let cliargs = App::new("at51")
        .version("0.1.1")
        .about("Applications for reverse engineering architecture 8051 firmware")
        .subcommand(
            SubCommand::with_name("base")
                .about("Finds the base address of a firmware file")
                .arg(
                    Arg::with_name("acall")
                        .help("Use offsets from ajmp/acall [default: no]")
                        .short("a")
                        .long("acall"),
                )
                .arg(
                    Arg::with_name("index-count")
                        .help("Output the n most fitting indexes")
                        .short("n")
                        .long("index-count")
                        .takes_value(true)
                        .default_value("3"),
                )
                .arg(
                    Arg::with_name("file")
                        .help("File to find base address of")
                        .required(true)
                        .multiple(true)
                        .min_values(1)
                        .max_values(32)
                        .index(1),
                ),
        )
        .subcommand(
            SubCommand::with_name("libfind")
                .about("Finds occurences of standard library functions in file")
                .arg(
                    Arg::with_name("no-check")
                        .help("Don't check if direct segment references are valid (more noise)")
                        .short("n")
                        .long("no-check"),
                )
                .arg(
                    Arg::with_name("file")
                        .help("File to find functions in")
                        .required(true)
                        .index(1),
                )
                .arg(
                    Arg::with_name("libraries")
                        .help("OMF51 Libraries to take definitions from")
                        .required(true)
                        .multiple(true)
                        .min_values(1)
                        .index(2),
                ),
        )
        .subcommand(
            SubCommand::with_name("stat")
                .about("Shows statistical information about 8051 instruction frequency")
                .arg(
                    Arg::with_name("blocksize")
                        .help("Blocksize of the square-chi test")
                        .short("b")
                        .long("blocksize")
                        .takes_value(true)
                        .default_value("512"),
                )
                .arg(
                    Arg::with_name("kullback-leibler")
                        .help("Use Kullback-Leibler divergence instead of square-chi")
                        .short("k")
                        .long("kullback-leibler"),
                )
                .arg(
                    Arg::with_name("corpus")
                        .help("Use a file to derive the frequencies")
                        .short("c")
                        .long("corpus")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("file")
                        .help("File to find 8051 instruction frequencies of")
                        .required(true)
                        .index(1),
                ),
        )
        .subcommand(
            SubCommand::with_name("kinit")
                .about("Shows the initialized variables of the Keil init segment")
                .arg(
                    Arg::with_name("offset")
                        .help("Location of Keil init data structure")
                        .short("o")
                        .long("offset")
                        .takes_value(true)
                        .default_value("0"),
                )
                .arg(
                    Arg::with_name("file")
                        .help("File to find Keil Init structure in")
                        .required(true)
                        .index(1),
                ),
        )
        .get_matches();
    match cliargs.subcommand() {
        ("base", Some(base_arg)) => {
            // list of files to find out alignment of
            let filenames = base_arg.values_of("file").unwrap();
            let nfiles = filenames.len();
            let mut mean: Vec<f64> = vec![1.0; 0x10000];
            let acall = base_arg.is_present("acall");
            let num: usize = base_arg
                .value_of("index-count")
                .unwrap()
                .parse()
                .unwrap_or_else(|err| {
                    eprintln!("Could not read index count: {}", err);
                    process::exit(2);
                });
            for name in filenames {
                let f = File::open(name).unwrap_or_else(|err| {
                    eprintln!("Could not open file '{}': {}", name, err);
                    process::exit(2);
                });
                let mut buf = vec![0; 0x10000];
                // read only the first 2^16 bytes, since the algorithm wouldn't work otherwise
                f.take(0x10000).read_to_end(&mut buf).unwrap_or_else(|err| {
                    eprintln!("Could not read file '{}': {}", name, err);
                    process::exit(2);
                });
                let match_array = base::find_base(&buf, acall);
                mean = mean
                    .iter()
                    .zip(match_array.iter())
                    .map(|(x, y)| x + y)
                    .collect();
                if nfiles > 1 {
                    let (best_index, best_value) = base::maxidx(&match_array, 1)[0];
                    println!(
                        "Best index of '{}': {:#04x} with {}",
                        name, best_index, best_value
                    );
                }
            }
            mean = mean
                .iter()
                .map(|x| x / base_arg.occurrences_of("file") as f64)
                .collect();
            println!("Index by likeliness:");
            for (i, (index, value)) in base::maxidx(&mean, num).iter().enumerate() {
                println!("\t{}: {:#04x} with {}", i + 1, index, value);
            }
        }
        ("libfind", Some(find_arg)) => {
            let filename = find_arg.value_of("file").unwrap();
            let contents = read_whole_file_by_name(filename);
            let mut pubnames: Vec<Vec<String>> = vec![Vec::new(); contents.len()];
            let mut refnames: Vec<Vec<String>> = vec![Vec::new(); 0x10000];
            let check = !find_arg.is_present("no-check");
            let libnames = find_arg.values_of("libraries").unwrap();
            for libname in libnames {
                let buffer = read_whole_file_by_name(libname);
                let parsed = libfind::omf51::Omf51Objects::new(&buffer).unwrap_or_else(|err| {
                    eprintln!("Could not parse file '{}': {:?}", libname, err);
                    process::exit(2);
                });
//                println!("{:#?}", parsed);
                let modseg: libfind::SegmentCollection = parsed.try_into().unwrap_or_else(|err| {
                    eprintln!("Invalid file content of '{}': {}", libname, err);
                    process::exit(2);
                });
                modseg.find_segments(&contents, &mut pubnames, &mut refnames, check);
            }
            let segrefs = libfind::process_segrefs(&mut pubnames, &mut refnames);
            libfind::print_segrefs(&segrefs);
        }
        ("stat", Some(stat_arg)) => {
            let filename = stat_arg.value_of("file").unwrap();
            let contents = read_whole_file_by_name(filename);
            let blocksize: usize = stat_arg
                .value_of("blocksize")
                .unwrap()
                .parse()
                .unwrap_or_else(|err| {
                    eprintln!("Could not read blocksize: {}", err);
                    process::exit(2);
                });
            let corpus = stat_arg.value_of("corpus").map(|f| {
                stat::FreqInfo::new(
                    &[32, 32, 32, 32, 16, 16, 16, 16, 8, 8, 8, 8, 8, 8, 8, 8],
                    &read_whole_file_by_name(f),
                )
                .unwrap_or_else(|err| {
                    eprintln!("Error deriving from Corpus: {}", err);
                    process::exit(2);
                })
            });
            let statfunction = if stat_arg.is_present("kullback-leibler") {
                stat::kullback_leibler
            } else {
                stat::square_chi
            };
            let blocks = stat::stat_blocks(&contents, blocksize, statfunction, corpus.as_ref());
            for (i, x) in blocks.iter().enumerate() {
                println!("{:#04x}: {}", i * blocksize, x);
            }
        }
        ("kinit", Some(kinit_arg)) => {
            let filename = kinit_arg.value_of("file").unwrap();
            let contents = read_whole_file_by_name(filename);
            let offset: usize = kinit_arg
                .value_of("offset")
                .unwrap()
                .parse()
                .unwrap_or_else(|err| {
                    eprintln!("Could not read offset: {}", err);
                    process::exit(2);
                });
            let init_data = kinit::InitData::new(&contents[offset..]).unwrap_or_else(|_| {
                eprintln!("Error parsing data structure");
                process::exit(2);
            });
            init_data.print();
        }
        _ => {
            println!("{}", cliargs.usage());
            process::exit(1);
        }
    }
}

fn read_whole_file_by_name(filename: &str) -> Vec<u8> {
    let mut file = File::open(filename).unwrap_or_else(|err| {
        eprintln!("Could not open file '{}': {}", filename, err);
        process::exit(2);
    });
    let mut contents = Vec::new();
    file.read_to_end(&mut contents).unwrap_or_else(|err| {
        eprintln!("Could not read file '{}': {}", filename, err);
        process::exit(2);
    });
    contents
}
