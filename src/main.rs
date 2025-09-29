use clap::Parser;
use anyhow::Result;

mod cli;
mod crypto;
mod file;

use cli::{Cli, Operation};
use crypto::AesEcb;
use file::{read_file, write_file};

fn main() -> Result<()> {
    let cli = Cli::parse();
    
    if let Err(e) = cli.validate() {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }

    let output_path = cli.get_output_path();
    let input_data = read_file(&cli.input)?;

    let output_data = match cli.operation {
        Operation::Encrypt => {
            let aes = AesEcb::new(&cli.key)?;
            aes.encrypt(&input_data)?
        }
        Operation::Decrypt => {
            let aes = AesEcb::new(&cli.key)?;
            aes.decrypt(&input_data)?
        }
    };

    write_file(&output_path, &output_data)?;

    println!("Operation completed successfully!");
    println!("Output: {}", output_path.display());

    Ok(())
}