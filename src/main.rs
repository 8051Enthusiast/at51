pub mod base;
mod conf;
mod instr;
pub mod kinit;
pub mod libfind;
pub mod stat;

use clap::{App, Arg, ArgGroup, SubCommand};
use conf::StatMode;
use std::fs::File;
use std::io::Read;
use std::process;

fn main() {
    let cliargs = App::new("at51")
        .version("1.0.0")
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
                    Arg::with_name("json")
                        .help("Output JSON (warning: outputs array of length 65536)")
                        .short("j")
                        .long("json"),
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
                    Arg::with_name("cyclic")
                        .help("Shifts firmware cyclically inside 64k address space instead of moving it out of the space")
                        .short("c")
                        .long("cyclic")
                )
                .arg(
                    Arg::with_name("dump")
                        .help("Dump the likeliness values of every address (warning: long)")
                        .short("d")
                        .long("dump")
                )
                .arg(
                    Arg::with_name("file")
                        .help("File to find base address of")
                        .required(true)
                        .multiple(true)
                        .min_values(1)
                        .max_values(32)
                        .index(1),
                )
        )
        .subcommand(
            SubCommand::with_name("libfind")
                .about("Finds occurences of standard library functions in file")
                .arg(
                    Arg::with_name("json")
                        .help("Output JSON")
                        .short("j")
                        .long("json"),
                )
                .arg(
                    Arg::with_name("no-check")
                        .help("Do not check if direct segment references are valid (more noise)")
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
                        .multiple(true)
                        .min_values(0)
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
                    Arg::with_name("corpus")
                        .help("Use a file to derive the frequencies")
                        .short("c")
                        .long("corpus")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("json")
                        .help("Output JSON")
                        .short("j")
                        .long("json"),
                )
                .arg(
                    Arg::with_name("kullback-leibler")
                        .help("Use Kullback-Leibler divergence (default)")
                        .short("k")
                        .long("kullback-leibler"),
                )
                .arg(
                    Arg::with_name("chi-squared")
                        .help("Use chi-squared error")
                        .short("x")
                        .long("chi-squared"),
                )
                .arg(
                    Arg::with_name("aligned-jump")
                        .help("Use percentage of non-aligned jumps")
                        .short("a")
                        .long("aligned-jump")
                )
                .arg(
                    Arg::with_name("count-absolute")
                        .help("When using aligned-jump, also include absolute jumps")
                        .short("A")
                        .long("count-absolute")
                )
                .arg(
                    Arg::with_name("count-outside")
                        .help("When using aligned-jump, also include jumps to outside of firmware as misses")
                        .short("O")
                        .long("count-outside")
                )
                .arg(
                    Arg::with_name("number-data")
                        .help("Also outputs the number of datapoints used in each block")
                        .short("n")
                        .long("number-data")
                )
                .arg(
                    Arg::with_name("file")
                        .help("File to get 8051 statistics from")
                        .required(true)
                        .index(1),
                )
            .group(ArgGroup::with_name("mode")
                   .args(&["kullback-leibler", "chi-squared", "aligned-jump"]))
        )
        .subcommand(
            SubCommand::with_name("kinit")
                .about("Shows the initialized variables of the Keil init segment")
                .arg(
                    Arg::with_name("json")
                        .help("Output JSON")
                        .short("j")
                        .long("json"),
                )
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
    let conf = conf::get_config();
    match cliargs.subcommand() {
        // base handling
        ("base", Some(base_arg)) => {
            // list of files to find out alignment of
            let filenames = base_arg.values_of("file").unwrap();
            let nfiles = filenames.len();
            let mut mean: Vec<f64> = vec![1.0; 0x20000];
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
                let mut buf = Vec::new();
                // read only the first 2^16 bytes, since the algorithm wouldn't work otherwise
                // and it is unclear what it would mean for 16-bit firmware
                f.take(0x10000).read_to_end(&mut buf).unwrap_or_else(|err| {
                    eprintln!("Could not read file '{}': {}", name, err);
                    process::exit(2);
                });
                let match_array = base::find_base(&buf, acall, base_arg.is_present("cyclic"));
                mean = mean
                    .iter()
                    .zip(match_array.iter())
                    .map(|(x, y)| x + y)
                    .collect();
                if nfiles > 1 && !base_arg.is_present("json") && !base_arg.is_present("dump") {
                    let (best_index, best_value) = base::maxidx(&match_array, 1)[0];
                    let idx: isize = if best_index >= 0x10000 {
                        best_index as isize - 2 * 0x10000
                    } else {
                        best_index as isize
                    };
                    println!("Best index of '{}': {:#04x} with {}", name, idx, best_value);
                }
            }
            mean = mean
                .iter()
                .map(|x| x / base_arg.occurrences_of("file") as f64)
                .collect();
            match (base_arg.is_present("dump"), base_arg.is_present("json")) {
                (true, true) => {
                    let json_str = serde_json::to_string(&mean).unwrap_or_else(|err| {
                        eprintln!("Could not create json: {}", err);
                        process::exit(2);
                    });
                    println!("{}", json_str);
                }
                (true, false) => {
                    for x in mean {
                        println!("{}", x);
                    }
                }
                (false, true) => {
                    let json_str =
                        serde_json::to_string(&base::maxidx(&mean, num)).unwrap_or_else(|err| {
                            eprintln!("Could not create json: {}", err);
                            process::exit(2);
                        });
                    println!("{}", json_str);
                }
                (false, false) => {
                    println!("Index by likeliness:");
                    for (i, (index, value)) in base::maxidx(&mean, num).iter().enumerate() {
                        let nidx: isize = if *index >= 0x10000 {
                            *index as isize - 2 * 0x10000
                        } else {
                            *index as isize
                        };
                        let sign = if nidx < 0 { '-' } else { ' ' };
                        println!("\t{}: {}{:#04x} with {}", i + 1, sign, nidx.abs(), value);
                    }
                }
            }
        }

        // libfind handling
        ("libfind", Some(find_arg)) => {
            let filename = find_arg.value_of("file").unwrap();
            let contents = read_whole_file_by_name(filename);
            let check = !find_arg.is_present("no-check");
            let mut libnames: Vec<_> = find_arg
                .values_of("libraries")
                .unwrap_or_default()
                .collect();
            if libnames.is_empty() {
                libnames = match &conf.libraries {
                    Some(libs) => libs.iter().map(|x| x.as_str()).collect(),
                    None => Vec::new(),
                }
            }
            if libnames.is_empty() {
                eprintln!("No libraries given and none in config");
                process::exit(2);
            }
            let (mut pubnames, mut refnames) = libfind::read_libraries(&libnames, &contents, check)
                .unwrap_or_else(|err| {
                    eprintln!("Could not process library files: {}", err);
                    process::exit(2);
                });
            let segrefs = libfind::process_segrefs(&mut pubnames, &mut refnames);
            if find_arg.is_present("json") {
                let json_str = serde_json::to_string(&segrefs).unwrap_or_else(|err| {
                    eprintln!("Could not print json: {}", err);
                    process::exit(2);
                });
                println!("{}", json_str);
            } else {
                println!("Library functions found for {}:", filename);
                libfind::print_segrefs(&segrefs);
            }
        }

        // stat handling
        ("stat", Some(stat_arg)) => {
            let filename = stat_arg.value_of("file").unwrap();
            let contents = read_whole_file_by_name(filename);
            let mode = if stat_arg.is_present("chi-squared") {
                StatMode::SquareChi
            } else if stat_arg.is_present("kullback-leibler") {
                StatMode::KullbackLeibler
            } else if stat_arg.is_present("aligned-jump") {
                StatMode::AlignedJump
            } else {
                conf.stat_mode.unwrap_or_default()
            };
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
            let blocks = match mode {
                StatMode::SquareChi => {
                    stat::stat_blocks(&contents, blocksize, stat::square_chi, corpus.as_ref())
                }
                StatMode::KullbackLeibler => stat::stat_blocks(
                    &contents,
                    blocksize,
                    stat::kullback_leibler,
                    corpus.as_ref(),
                ),
                StatMode::AlignedJump => stat::instr_align_count(
                    &contents,
                    blocksize,
                    stat_arg.is_present("count-absolute"),
                    stat_arg.is_present("count-outside"),
                ),
            };
            let is_n = stat_arg.is_present("number-data");
            if stat_arg.is_present("json") {
                let json_str = if is_n {
                    serde_json::to_string(&blocks)
                } else {
                    serde_json::to_string(&blocks.iter().map(|(x, _)| x).collect::<Vec<_>>())
                }
                .unwrap_or_else(|err| {
                    eprintln!("Could not print json: {}", err);
                    process::exit(2);
                });
                println!("{}", json_str);
            } else {
                for (i, (x, n)) in blocks.iter().enumerate() {
                    if is_n {
                        println!("{:#04x}: {} {}", i * blocksize, x, n)
                    } else {
                        println!("{:#04x}: {}", i * blocksize, x)
                    }
                }
            }
        }

        // kinit handling
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
            if kinit_arg.is_present("json") {
                let json_str = serde_json::to_string(&init_data).unwrap_or_else(|err| {
                    eprintln!("Could not print json: {}", err);
                    process::exit(2);
                });
                println!("{}", json_str);
            } else {
                init_data.print();
            }
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
