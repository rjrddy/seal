use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use seal_log::{
    Checkpoint, Consistency, Error, Inclusion, Result, hash_from, require,
    storage::{Store, read_entries},
    verify_log,
};
use serde_json::json;
use std::{
    env, fs,
    path::{Path, PathBuf},
};
mod benchmark;
mod web;
fn read_key(path: &str) -> Result<SigningKey> {
    let text = fs::read_to_string(path)?;
    Ok(SigningKey::from_bytes(&hash_from(text.trim())?))
}
fn public(text: &str) -> Result<VerifyingKey> {
    VerifyingKey::from_bytes(&hash_from(text)?).map_err(|_| Error("public key rejected".into()))
}
fn read_json<T: serde::de::DeserializeOwned>(path: &str) -> Result<T> {
    require(fs::metadata(path)?.len() <= 1048576, "JSON size limit")?;
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}
fn print_json(value: impl serde::Serialize) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}
fn run() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let get = |n: usize| {
        args.get(n)
            .map(String::as_str)
            .ok_or(Error("missing argument; run seal help".into()))
    };
    match get(1)? {
        "help" => {
            println!(
                "seal keygen <private-file>\nseal init <dir> <private-file> <log-id-hex>\nseal append <dir> <private-file> <log-id-hex> <payload-text>\nseal checkpoint <dir> <private-file> <log-id-hex>\nseal inclusion <entries-file> <checkpoint-file> <index>\nseal consistency <entries-file> <old-cp-file> <new-cp-file>\nseal verify-inclusion|verify-consistency <bundle-file> <trusted-public-key-hex> <trusted-log-id-hex>\nseal verify-log <entries-file> <checkpoint-file> <trusted-public-key-hex> <trusted-log-id-hex>\nseal serve <demo-dir>\nseal bench <results-dir>"
            );
            Ok(())
        }
        "keygen" => {
            let key = SigningKey::generate(&mut OsRng);
            let path = Path::new(get(2)?);
            let mut options = fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            use std::io::Write;
            let mut file = options.open(path)?;
            file.write_all(hex::encode(key.to_bytes()).as_bytes())?;
            file.sync_all()?;
            print_json(
                json!({"public_key":hex::encode(key.verifying_key().to_bytes()),"private_file":path,"key_source":"OS randomness"}),
            )
        }
        "init" | "append" | "checkpoint" => {
            let store = Store::create(Path::new(get(2)?), read_key(get(3)?)?, hash_from(get(4)?)?)?;
            if get(1)? == "append" {
                let entries = store.append_many(&[get(5)?.as_bytes().to_vec()], true)?;
                print_json(
                    json!({"size":entries.len(),"entry_fsynced":true,"checkpoint_interval":seal_log::storage::INTERVAL}),
                )
            } else {
                print_json(store.checkpoint()?)
            }
        }
        "inclusion" => {
            let entries = read_entries(Path::new(get(2)?))?;
            let cp: Checkpoint = read_json(get(3)?)?;
            let index = get(4)?
                .parse::<usize>()
                .map_err(|_| Error("index".into()))?;
            print_json(Inclusion::create(&entries, index, cp)?)
        }
        "consistency" => {
            let entries = read_entries(Path::new(get(2)?))?;
            print_json(Consistency::create(
                &entries,
                read_json(get(3)?)?,
                read_json(get(4)?)?,
            )?)
        }
        "verify-inclusion" | "verify-consistency" => {
            let key = public(get(3)?)?;
            let log_id = hash_from(get(4)?)?;
            if get(1)? == "verify-inclusion" {
                read_json::<Inclusion>(get(2)?)?.verify(&key, log_id)?;
            } else {
                read_json::<Consistency>(get(2)?)?.verify(&key, log_id)?;
            }
            print_json(json!({"verified":true,"trust":"caller-pinned public key and log identity"}))
        }
        "verify-log" => {
            verify_log(
                &read_entries(Path::new(get(2)?))?,
                &read_json(get(3)?)?,
                &public(get(4)?)?,
                hash_from(get(5)?)?,
            )?;
            print_json(json!({"verified":true,"tail":"matches caller-pinned checkpoint"}))
        }
        "bench" => benchmark::run(Path::new(get(2)?)),
        "serve" => web::serve(PathBuf::from(get(2)?)),
        _ => Err(Error("unknown command; run seal help".into())),
    }
}
fn main() {
    if let Err(error) = run() {
        eprintln!("{}", json!({"verified":false,"error":error.to_string()}));
        std::process::exit(1);
    }
}
