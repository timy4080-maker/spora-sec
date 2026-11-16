use anyhow::{Result, ensure};
use clap::{Parser, Subcommand};
use spora_sec::{Client, Invitation, transport::HttpTransport};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    about = "SEC-01 libsignal prototype. External security review pending; artificial test messages only."
)]
struct Args {
    #[arg(long)]
    profile: PathBuf,
    /// Explicit insecure file key for automated tests; never a fallback for DPAPI.
    #[arg(long)]
    allow_test_key: bool,
    #[arg(long)]
    ca: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Init,
    Identity,
    Status,
    Messages,
    Queues,
    Queue {
        #[arg(long)]
        endpoint: String,
        #[arg(long)]
        provisioning_token_file: PathBuf,
        #[arg(long)]
        existing_queue: Option<String>,
    },
    Invite {
        #[arg(long)]
        request: String,
        #[arg(long)]
        for_fingerprint: String,
        #[arg(long)]
        output: PathBuf,
    },
    Import {
        #[arg(long)]
        invitation: PathBuf,
        #[arg(long)]
        expected_fingerprint: String,
        #[arg(long)]
        conversation: String,
    },
    Send {
        #[arg(long)]
        request: String,
        #[arg(long, value_delimiter = ',')]
        peers: Vec<String>,
        #[arg(long)]
        text: String,
    },
    Dispatch,
    Fetch,
    Consume,
    Apply,
    Receipts,
    Tick,
    RetryAttention,
}
fn output(value: impl serde::Serialize) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}
fn main() {
    if let Err(error) = run(Args::parse()) {
        eprintln!("{error:#}");
        std::process::exit(1);
    }
}
fn run(args: Args) -> Result<()> {
    if matches!(args.command, Command::Init) {
        let c = Client::create(&args.profile, args.allow_test_key)?;
        return output(
            serde_json::json!({"device":c.device()?,"fingerprint":c.device()?.fingerprint(),"external_review":"pending"}),
        );
    }
    let mut c = Client::open(&args.profile, args.allow_test_key)?;
    let now = spora_core::now_ms();
    match args.command {
        Command::Init => unreachable!(),
        Command::Identity => output(
            serde_json::json!({"device":c.device()?,"fingerprint":c.device()?.fingerprint()}),
        ),
        Command::Status => output(c.status()?),
        Command::Messages => output(c.messages()?),
        Command::Queues => output(c.queues()?),
        Command::Invite {
            request,
            for_fingerprint,
            output: path,
        } => {
            let inv = c.invite(&request, &for_fingerprint, now)?;
            // The transaction precedes file output. A lost output is safely re-exported
            // with the same request ID without allocating another prekey.
            let bytes = serde_json::to_vec_pretty(&inv)?;
            if path.exists() {
                ensure!(
                    std::fs::read(&path)? == bytes,
                    "output already exists with different invitation"
                );
            } else {
                use std::io::Write;
                let mut opts = std::fs::OpenOptions::new();
                opts.write(true).create_new(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    opts.mode(0o600);
                }
                let mut f = opts.open(path)?;
                f.write_all(&bytes)?;
                f.sync_all()?;
            }
            output(serde_json::json!({"invitation_id":inv.body.invitation_id,"bytes":bytes.len()}))
        }
        Command::Import {
            invitation,
            expected_fingerprint,
            conversation,
        } => {
            ensure!(
                std::fs::metadata(&invitation)?.len() <= 65536,
                "invitation too large"
            );
            let inv: Invitation = serde_json::from_slice(&std::fs::read(invitation)?)?;
            output(c.import(inv, &expected_fingerprint, &conversation, now)?)
        }
        Command::Send {
            request,
            peers,
            text,
        } => output(c.send(&request, &peers, &text, now)?),
        Command::Apply => output(c.apply(now)?),
        Command::Receipts => output(c.prepare_receipts(now)?),
        Command::RetryAttention => {
            c.retry_attention()?;
            output(c.status()?)
        }
        command => {
            let t = HttpTransport::new(args.ca.as_deref())?;
            match command {
                Command::Queue {
                    endpoint,
                    provisioning_token_file,
                    existing_queue,
                } => {
                    let service = t.service_id(&endpoint)?;
                    let queue = match existing_queue {
                        Some(q) => q,
                        None => c.add_source(&service, &endpoint)?,
                    };
                    let token = std::fs::read_to_string(provisioning_token_file)?;
                    // Queue capabilities are committed before the idempotent network request.
                    t.provision(&endpoint, token.trim(), &c.queue_request(&queue)?)?;
                    output(queue)
                }
                Command::Dispatch => output(c.dispatch(&t, now)?),
                Command::Fetch => output(c.fetch(&t, now)?),
                Command::Consume => output(c.consume(&t, now)?),
                Command::Tick => {
                    c.fetch(&t, now)?;
                    c.consume(&t, now)?;
                    c.apply(now)?;
                    c.prepare_receipts(now)?;
                    c.dispatch(&t, now)?;
                    output(c.status()?)
                }
                _ => unreachable!(),
            }
        }
    }
}
