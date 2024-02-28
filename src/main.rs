pub mod base;
mod conf;
mod instr;
pub mod kinit;
pub mod libfind;
pub mod stat;

use clap::{arg, Parser, Subcommand};
use conf::StatMode;
use std::fs::File;
use std::io::Read;
use std::process::{self};

#[derive(Parser, Debug)]
struct Base {
    /// Use offsets from ajmp/acall [default: no]
    #[arg(short, long)]
    acall: bool,
    /// Output JSON (warning: outputs array of length 65536)
    #[arg(short, long)]
    json: bool,
    /// Output the n most fitting indexes
    #[arg(short, long, default_value_t = 3)]
    index_count: usize,
    /// Shifts firmware cyclically inside 64k address space instead of moving it out of the space
    #[arg(short, long)]
    cyclic: bool,
    /// Dump the likeliness values of every address (warning: long)
    #[arg(short, long)]
    dump: bool,
    /// File to find base address of
    #[arg(index = 1)]
    file: Vec<String>,
}

#[derive(Parser, Debug)]
struct Libfind {
    /// Output JSON
    #[arg(short, long)]
    json: bool,
    /// Do not check if direct segment references are valid (more noise)
    #[arg(short, long)]
    no_check: bool,
    /// File to find functions in
    #[arg(index = 1)]
    file: String,
    /// OMF51 Libraries to take definitions from
    #[arg(index = 2)]
    libraries: Vec<String>,
    /// Minimum length of function to match, excluding fixed up addresses (in bytes)
    #[arg(short, long, default_value_t = 4)]
    min_fn_length: usize,
    /// Skip addresses where more than n functions are found
    #[arg(short, long)]
    skip_multiple: Option<usize>,
}

#[derive(Parser, Debug)]
struct Stat {
    /// Blocksize of the square-chi test
    #[arg(short, long, default_value_t = 512)]
    blocksize: usize,
    /// Use a file to derive the frequencies
    #[arg(short, long)]
    corpus: Option<String>,
    /// Output JSON
    #[arg(short, long)]
    json: bool,
    /// Use Kullback-Leibler divergence
    #[arg(short, long)]
    kullback_leibler: bool,
    /// Use chi-squared error
    #[arg(short, long)]
    chi_squared: bool,
    /// Use percentage of non-aligned jumps (default)
    #[arg(short, long)]
    aligned_jump: bool,
    /// When using aligned-jump, also include absolute jumps
    #[arg(short, long)]
    count_absolute: bool,
    /// When using aligned-jump, also include jumps to outside of firmware as misses
    #[arg(short, long)]
    count_outside: bool,
    /// Also outputs the number of datapoints used in each block
    #[arg(short, long)]
    number_data: bool,
    /// File to get 8051 statistics from
    #[arg(index = 1)]
    file: String,
}

#[derive(Parser, Debug)]
struct Kinit {
    /// Output JSON
    #[arg(short, long)]
    json: bool,
    /// Location of Keil init data structure
    #[arg(short, long, default_value_t = 0)]
    offset: usize,
    /// File to find Keil Init structure in
    #[arg(index = 1)]
    file: String,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Finds the base address of a firmware file
    Base(Base),
    /// Finds occurences of standard library functions in file
    Libfind(Libfind),
    /// Shows statistical information about 8051 instruction frequency
    Stat(Stat),
    /// Shows the initialized variables of the Keil init segment
    Kinit(Kinit),
}

#[derive(Parser, Debug)]
struct Cli {
    /// Applications for reverse engineering architecture 8051 firmware
    #[command(subcommand)]
    subcommand: Cmd,
}

fn main() {
    let cliargs = Cli::parse();
    let conf = conf::get_config();
    match cliargs.subcommand {
        Cmd::Base(Base {
            acall,
            json,
            index_count,
            cyclic,
            dump,
            file,
        }) => {
            // list of files to find out alignment of
            let nfiles = file.len();
            let mut mean: Vec<f64> = vec![1.0; 0x20000];
            for name in file.iter() {
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
                let match_array = base::find_base(&buf, acall, cyclic);
                mean = mean
                    .iter()
                    .zip(match_array.iter())
                    .map(|(x, y)| x + y)
                    .collect();
                if nfiles > 1 && !json && !dump {
                    let (best_index, best_value) = base::maxidx(&match_array, 1)[0];
                    let idx: isize = if best_index >= 0x10000 {
                        best_index as isize - 2 * 0x10000
                    } else {
                        best_index as isize
                    };
                    println!("Best index of '{}': {:#04x} with {}", name, idx, best_value);
                }
            }
            mean = mean.iter().map(|x| x / file.len() as f64).collect();
            match (dump, json) {
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
                    let json_str = serde_json::to_string(&base::maxidx(&mean, index_count))
                        .unwrap_or_else(|err| {
                            eprintln!("Could not create json: {}", err);
                            process::exit(2);
                        });
                    println!("{}", json_str);
                }
                (false, false) => {
                    println!("Index by likeliness:");
                    for (i, (index, value)) in base::maxidx(&mean, index_count).iter().enumerate() {
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

        Cmd::Libfind(Libfind {
            json,
            no_check,
            file,
            mut libraries,
            min_fn_length,
            skip_multiple,
        }) => {
            let contents = read_whole_file_by_name(&file);
            let check = !no_check;
            if libraries.is_empty() {
                libraries = conf.libraries.clone().unwrap_or_default();
            }
            if libraries.is_empty() {
                eprintln!("No libraries given and none in config");
                process::exit(2);
            }
            let (mut pubnames, mut refnames) =
                libfind::read_libraries(&libraries, &contents, check, min_fn_length)
                    .unwrap_or_else(|err| {
                        eprintln!("Could not process library files: {}", err);
                        process::exit(2);
                    });
            let segrefs = libfind::process_segrefs(&mut pubnames, &mut refnames, skip_multiple);
            if json {
                let json_str = serde_json::to_string(&segrefs).unwrap_or_else(|err| {
                    eprintln!("Could not print json: {}", err);
                    process::exit(2);
                });
                println!("{}", json_str);
            } else {
                println!("Library functions found for {}:", file);
                libfind::print_segrefs(&segrefs);
            }
        }

        Cmd::Stat(Stat {
            blocksize,
            corpus,
            json,
            kullback_leibler,
            chi_squared,
            aligned_jump,
            count_absolute,
            count_outside,
            number_data,
            file,
        }) => {
            let contents = read_whole_file_by_name(&file);
            let mode = if chi_squared {
                StatMode::SquareChi
            } else if kullback_leibler {
                StatMode::KullbackLeibler
            } else if aligned_jump {
                StatMode::AlignedJump
            } else {
                conf.stat_mode.unwrap_or_default()
            };
            let corpus = corpus.map(|f| {
                stat::FreqInfo::new(
                    &[32, 32, 32, 32, 16, 16, 16, 16, 8, 8, 8, 8, 8, 8, 8, 8],
                    &read_whole_file_by_name(&f),
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
                StatMode::AlignedJump => {
                    stat::instr_align_count(&contents, blocksize, count_absolute, count_outside)
                }
            };
            if json {
                let json_str = if number_data {
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
                    if number_data {
                        println!("{:#04x}: {} {}", i * blocksize, x, n)
                    } else {
                        println!("{:#04x}: {}", i * blocksize, x)
                    }
                }
            }
        }

        Cmd::Kinit(Kinit { json, offset, file }) => {
            let contents = read_whole_file_by_name(&file);
            let init_data = kinit::InitData::new(&contents[offset..]).unwrap_or_else(|_| {
                eprintln!("Error parsing data structure");
                process::exit(2);
            });
            if json {
                let json_str = serde_json::to_string(&init_data).unwrap_or_else(|err| {
                    eprintln!("Could not print json: {}", err);
                    process::exit(2);
                });
                println!("{}", json_str);
            } else {
                init_data.print();
            }
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
