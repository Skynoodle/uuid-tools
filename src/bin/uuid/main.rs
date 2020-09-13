use mac_address::{get_mac_address, mac_address_by_name, MacAddress};
use std::{convert::TryInto, fmt, process::exit, str::FromStr, time::SystemTime};
use structopt::StructOpt;
use uuid::Uuid;

#[derive(StructOpt, Debug, Clone)]
/// A simple command-line tool for generating and inspecting UUIDs
///
/// By default, uuid will accept an optional uuid argument, write all
/// successfully decoded or generated uuids to stdout, write other diagnostic
/// information to stderr, and return a success or failure exit code indicating
/// the validity of a provided uuid. Use the long form `--help` flag for more
/// detailed help output
struct Opt {
    /// A uuid in any of the supported formats (see `-o <output-format>`
    /// documentation for details). If omitted, `uuid` will generate a new
    /// uuid
    #[structopt(parse(try_from_str = parse_uuid))]
    uuid: Option<Uuid>,
    /// The version of uuid to generate or inspect
    ///
    /// When used to inspect an existing uuid, this rejects uuids of different
    /// versions - in this case `uuid` will return a failure exit code, and will
    /// not write the decoded uuid to stdout
    ///
    /// Supported versions for inspecting:
    ///
    /// - `0`: A nil (all-zeros) uuid
    ///
    /// - `1`: A datetime + MAC address uuid
    ///
    /// - `2`: A datetime + MAC address 'DCE security' uuid
    ///
    /// - `3`: An MD5-hashed namespace + name uuid
    ///
    /// - `4`: A random uuid
    ///
    /// - `5`: A SHA1-hashed namespace + name uuid
    ///
    /// Supported versions for generating:
    ///
    /// - `0`: A nil (all-zeros) uuid
    ///
    /// - `1`: A datetime + MAC address uuid
    ///
    /// - `4`: A random uuid
    ///
    #[structopt(short = "v", long = "version")]
    version_mode: Option<VersionMode>,
    /// The output format to use when writing the generated or decoded uuid to
    /// stdout
    ///
    /// Supported formats (these also correspond to formats for decoding):
    ///
    /// - `simple`: A compact form with no extra characters
    ///     (e.g `5c16fcb176ba4b068fdf34a6aeb478c5`)
    ///
    /// - `hyphenated`: Standard uuid form including hyphens
    ///     (e.g `5c16fcb1-76ba-4b06-8fdf-34a6aeb478c5`)
    ///
    /// - `urn`: The Unified Resource Name form of a uuid
    ///     (e.g `urn:uuid:5c16fcb1-76ba-4b06-8fdf-34a6aeb478c5`)
    ///
    /// - `ms`: hyphenated form surrounded by braces, as used by microsoft
    ///     (e.g `{5c16fcb1-76ba-4b06-8fdf-34a6aeb478c5}`)
    ///
    #[structopt(short = "o", long)]
    output_format: Option<Format>,

    /// Counter value to use for generating v1 NodeID + Timestamp uuids
    ///
    /// If omitted, a random value is used to mitigate collisions
    #[structopt(long)]
    counter: Option<u16>,

    /// RFC4122 timestamp value to use for generating v1 NodeID + Timestamp uuids
    ///
    /// If omitted, the current time is used
    #[structopt(long)]
    timestamp_ticks: Option<u64>,

    /// MAC Address to use for generating v1 NodeID + Timestamp uuids
    ///
    /// If omitted, the mac address of the interface specified by either
    /// `--mac-interface` or a non-local-loopback interface is used
    #[structopt(long)]
    mac_address: Option<MacAddress>,

    /// Interface name from which to obtain the the mac address for generating
    /// v1 NodeID + Timestamp uuids
    ///
    /// If omitted, the mac address of a non-local-loopback interface is used
    #[structopt(long)]
    mac_interface: Option<String>,
}

/// Parse a uuid in formats supported by the uuid crate, allowing for surrounding
/// braces for ms format
fn parse_uuid(s: &str) -> Result<Uuid, uuid::Error> {
    let s = if (34..=38).contains(&s.len()) && s.starts_with('{') && s.ends_with('}') {
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
            _ => return Err("invalid format name"),
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

pub struct VersionDesc(Option<uuid::Version>);

impl fmt::Display for VersionDesc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self.0 {
            Some(uuid::Version::Nil) => "Nil",
            Some(uuid::Version::Mac) => "v1 MAC Address",
            Some(uuid::Version::Dce) => "v2 DCE",
            Some(uuid::Version::Md5) => "v3 MD5",
            Some(uuid::Version::Random) => "v4 Random",
            Some(uuid::Version::Sha1) => "v5 SHA-1",
            None => "Unknown",
        })
    }
}

pub struct VariantDesc(Option<uuid::Variant>);

impl fmt::Display for VariantDesc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self.0 {
            Some(uuid::Variant::NCS) => "NCS",
            Some(uuid::Variant::RFC4122) => "RFC4122",
            Some(uuid::Variant::Microsoft) => "Microsoft",
            Some(uuid::Variant::Future) => "Reserved",
            None => "Unknown",
        })
    }
}

/// Calculate an RFC4122 tick timestamp value from a SystemTime
fn ticks_from_timestamp(time: SystemTime) -> u64 {
    let unix_time = time
        .duration_since(std::time::UNIX_EPOCH)
        .expect("Could not get duration since unix epoch");
    let seconds = unix_time.as_secs();
    let subsec_nanos = unix_time.subsec_nanos() as u64;
    seconds * 10000000 + subsec_nanos / 100
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
                eprintln!("error: Provided <uuid> did not match `--version-mode`");
                exit(1)
            }
        }
        uuid
    } else {
        match options.version_mode {
            Some(VersionMode(uuid::Version::Nil)) => Uuid::nil(),
            Some(VersionMode(uuid::Version::Mac)) => {
                let ticks = options.timestamp_ticks.unwrap_or_else(|| {
                    let now = SystemTime::now();
                    ticks_from_timestamp(now)
                });

                let counter = options.counter.unwrap_or(rand::random());

                let ts = uuid::v1::Timestamp::from_rfc4122(ticks, counter);

                let node_id =
                    options
                        .mac_address
                        .or_else(|| {
                            options.mac_interface.as_deref().map(|interface| {
                                match mac_address_by_name(interface).expect(&format!(
                                    "Could not get mac address for interface {}",
                                    interface
                                )) {
                                    Some(mac_address) => mac_address,
                                    None => {
                                        eprintln!("error: MAC address could not be obtained for `--mac-interface={}`", interface);
                                        exit(1)},
                                }
                            })
                        })
                        .or_else(|| get_mac_address().expect("Could not get mac address"))
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

    write!(stderr, "{}", VersionDesc(uuid.get_version())).expect("Could not write to stderr");

    write!(stderr, " {}", VariantDesc(uuid.get_variant())).expect("Could not write to stderr");

    writeln!(stderr).expect("Could not write to stderr");

    match uuid.get_version() {
        Some(uuid::Version::Mac) => {
            let (timestamp_ticks, counter) = uuid
                .to_timestamp()
                .map(|ts| ts.to_rfc4122())
                .unwrap_or((0, 0));

            let node_id = &uuid.as_bytes()[10..16];
            let mac = MacAddress::new(node_id.try_into().unwrap());
            writeln!(
                stderr,
                "timestamp_ticks={} counter={} node_id={}",
                timestamp_ticks, counter, mac
            )
            .expect("Could not write to stderr");
        }
        _ => (),
    }

    match options.output_format {
        Some(Format::Simple) => println!("{}", uuid::adapter::Simple::from_uuid(uuid)),
        Some(Format::Urn) => println!("{}", uuid::adapter::Urn::from_uuid(uuid)),
        Some(Format::Microsoft) => println!("{{{}}}", uuid::adapter::Hyphenated::from_uuid(uuid)),
        Some(Format::Hyphenated) | None => {
            println!("{}", uuid::adapter::Hyphenated::from_uuid(uuid))
        }
    }
}
