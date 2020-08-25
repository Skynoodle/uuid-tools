use std::{process::exit, str::FromStr};
use structopt::StructOpt;
use uuid::Uuid;

#[derive(StructOpt, Debug, Clone)]
struct Opt {
    #[structopt(parse(try_from_str = parse_uuid))]
    uuid: Option<Uuid>,
    #[structopt(short = "v", long = "version")]
    version_mode: Option<VersionMode>,
    #[structopt(short = "o", long = "output-format")]
    output_format: Option<Format>,
}

fn parse_uuid(s: &str) -> Result<Uuid, uuid::Error> {
    let s = if (34..=38).contains(&s.len())
        && s.chars()
            .next()
            .expect("could not get first character of non-empty string")
            == '{'
        && s.chars()
            .last()
            .expect("could not get last character of non-empty string")
            == '}'
    {
        &s[1..(s.len() - 1)]
    } else {
        s
    };
    s.parse()
}

#[derive(Debug, Clone)]
pub enum Format {
    Simple,
    Hyphenated,
    Urn,
    Microsoft,
}

impl FromStr for Format {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "simple" => Format::Simple,
            "hyphenated" => Format::Hyphenated,
            "urn" => Format::Urn,
            "ms" | "microsoft" => Format::Microsoft,
            _ => return Err("invalid format string"),
        })
    }
}

#[derive(Debug, Clone)]
pub struct VersionMode(uuid::Version);

impl FromStr for VersionMode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(VersionMode(
            match s.parse::<u8>().map_err(|e| e.to_string())? {
                0 => uuid::Version::Nil,
                1 => uuid::Version::Mac,
                2 => uuid::Version::Dce,
                3 => uuid::Version::Md5,
                4 => uuid::Version::Random,
                5 => uuid::Version::Sha1,
                _ => return Err("Version out of range".into()),
            },
        ))
    }
}

fn main() {
    let options = Opt::from_args();

    use std::io::Write;
    let stderr = std::io::stderr();
    let mut stderr = stderr.lock();

    let uuid = if let Some(uuid) = options.uuid {
        if let (Some(VersionMode(expected_version)), Some(version)) =
            (options.version_mode, uuid.get_version())
        {
            if expected_version != version {
                eprintln!("error: Provided <uuid> did not match <version-mode>");
                exit(1)
            }
        }

        write!(
            stderr,
            "{}",
            match uuid.get_version() {
                Some(uuid::Version::Nil) => "Nil",
                Some(uuid::Version::Mac) => "v1 MAC Address",
                Some(uuid::Version::Dce) => "v2 DCE",
                Some(uuid::Version::Md5) => "v3 MD5",
                Some(uuid::Version::Random) => "v4 Random",
                Some(uuid::Version::Sha1) => "v5 SHA-1",
                None => "Unknown",
            }
        )
        .expect("Could not write to stderr");

        write!(
            stderr,
            " {}",
            match uuid.get_variant() {
                Some(uuid::Variant::NCS) => "NCS",
                Some(uuid::Variant::RFC4122) => "RFC4122",
                Some(uuid::Variant::Microsoft) => "Microsoft",
                Some(uuid::Variant::Future) => "Reserved",
                None => "Unknown",
            }
        )
        .expect("Could not write to stderr");

        writeln!(stderr)
        .expect("Could not write to stderr");
        uuid
    } else {
        match options.version_mode {
            Some(VersionMode(uuid::Version::Nil)) => Uuid::nil(),
            Some(VersionMode(uuid::Version::Mac)) => {
                // We probably shouldn't do this
                let context = uuid::v1::Context::new(0);
                let now = std::time::SystemTime::now();
                let unix_time = now
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("Could not get duration since unix epoch");
                let seconds = unix_time.as_secs();
                let subsec_nanos = unix_time.subsec_nanos();
                let ts = uuid::v1::Timestamp::from_unix(context, seconds, subsec_nanos);
                let node_id = mac_address::get_mac_address()
                    .expect("Could not get mac address")
                    .expect("No mac address found");
                Uuid::new_v1(ts, &node_id.bytes()).expect("could not build uuid")
            }
            Some(VersionMode(uuid::Version::Random)) | None => Uuid::new_v4(),
            _ => {
                println!("error: Only 0, 1, and 4 are supported for '--version <version-mode>' without a provided <uuid>");
                exit(1);
            }
        }
    };

    match options.output_format {
        Some(Format::Simple) => println!("{}", uuid::adapter::Simple::from_uuid(uuid)),
        Some(Format::Urn) => println!("{}", uuid::adapter::Urn::from_uuid(uuid)),
        Some(Format::Microsoft) => println!("{{{}}}", uuid::adapter::Hyphenated::from_uuid(uuid)),
        Some(Format::Hyphenated) | None => {
            println!("{}", uuid::adapter::Hyphenated::from_uuid(uuid))
        }
    }
}
