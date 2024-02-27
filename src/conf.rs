use dirs::config_dir;
use serde::Deserialize;
use std::fs::File;

#[derive(Deserialize, Default)]
pub struct Conf {
    pub libraries: Option<Vec<String>>,
    pub stat_mode: Option<StatMode>,
}

#[derive(Deserialize, Default)]
pub enum StatMode {
    #[default]
    AlignedJump,
    SquareChi,
    KullbackLeibler,
}

pub fn get_config() -> Conf {
    match config_dir() {
        Some(mut path) => {
            path.push("at51");
            path.push("config.json");
            let file = File::open(path);
            match file {
                Ok(reader) => serde_json::from_reader(reader).unwrap_or_else(|err| {
                    eprintln!("Could not read config: {}", err);
                    Conf::default()
                }),
                Err(_) => Conf::default(),
            }
        }
        None => Conf::default(),
    }
}
