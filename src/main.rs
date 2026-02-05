use std::{
    env,
    ffi::OsString,
    fs::{ self, File },
    io::{ self, Write },
    path::{ Path, PathBuf },
    process::Command,
};

fn ziskej_velikost(cesta: &Path) -> io::Result<u128> {
    use std::io::{ Read, Seek, SeekFrom };

    let mut soubor = File::open(cesta)?;
    let mut buffer = [0u8; 64];

    soubor.read_exact(&mut buffer)?;

    if &buffer[0..2] != b"MZ" {
        return Ok(u128::from(fs::metadata(cesta)?.len()));
    }

    let pe_offset = u32::from_le_bytes([buffer[60], buffer[61], buffer[62], buffer[63]]);

    soubor.seek(SeekFrom::Start(u64::from(pe_offset)))?;
    let mut pe_buffer = [0u8; 24];
    soubor.read_exact(&mut pe_buffer)?;

    if &pe_buffer[0..4] != b"PE\0\0" {
        return Ok(u128::from(fs::metadata(cesta)?.len()));
    }

    let pocet_sekci = u16::from_le_bytes([pe_buffer[6], pe_buffer[7]]);
    let velikost_optional_header = u16::from_le_bytes([pe_buffer[20], pe_buffer[21]]);

    soubor.seek(SeekFrom::Start(u64::from(pe_offset) + 24 + u64::from(velikost_optional_header)))?;

    let mut max_konec = 0u64;
    for _ in 0..pocet_sekci {
        let mut sekce_buffer = [0u8; 40];
        soubor.read_exact(&mut sekce_buffer)?;

        let raw_velikost = u32::from_le_bytes([
            sekce_buffer[16],
            sekce_buffer[17],
            sekce_buffer[18],
            sekce_buffer[19],
        ]);
        let raw_offset = u32::from_le_bytes([
            sekce_buffer[20],
            sekce_buffer[21],
            sekce_buffer[22],
            sekce_buffer[23],
        ]);

        let konec_sekce = u64::from(raw_offset) + u64::from(raw_velikost);
        if konec_sekce > max_konec {
            max_konec = konec_sekce;
        }
    }

    Ok(u128::from(max_konec))
}

fn main() -> io::Result<()> {
    let exec_path = env::current_exe()?;
    let min_bajty = ziskej_velikost(&exec_path)?;
    let max_bajty = 4_u128 * 1024 * 1024 * 1024 - 1; // 4gb - 1b

    println!("enter target size in b, kb, mb, gb (e.g. 10mb)");
    println!("minimal allowed size: {}", formatuj_velikost(min_bajty));
    println!("maximal allowed size: {:.2} MB", (max_bajty as f64) / (1024_f64 * 1024_f64));

    let cilovy_bajty = ziskej_cilovy_bajty(min_bajty, max_bajty)?;
    let temp_path = priprav_temp_file(&exec_path, cilovy_bajty)?;
    spust_script(&exec_path, &temp_path)?;

    println!("the executable will change its size after exit", formatuj_velikost(cilovy_bajty));

    Ok(())
}

fn ziskej_cilovy_bajty(min: u128, max: u128) -> io::Result<u128> {
    let mut input = String::new();
    let varovaci_limit = 1_u128 * 1024 * 1024 * 1024; // 1gb

    loop {
        input.clear();
        print!("requested size: ");
        io::stdout().flush()?;
        io::stdin().read_line(&mut input)?;

        if let Some(hodnota) = preved_vstup_na_bajty(&input) {
            if hodnota < min {
                println!("minimum is {}", formatuj_velikost(min));
                continue;
            }

            if hodnota > max {
                println!("maximum is {}", formatuj_velikost(max));
                continue;
            }

            if hodnota >= varovaci_limit && !potvrd_velikost()? {
                println!("request cancelled");
                continue;
            }

            return Ok(hodnota);
        } else {
            println!("invalid input");
        }
    }
}

fn preved_vstup_na_bajty(input: &str) -> Option<u128> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return None;
    }

    let mut cisla = String::new();
    let mut jednotka = String::new();

    for znak in trimmed.chars() {
        if znak.is_ascii_digit() {
            if !jednotka.is_empty() {
                return None;
            }
            cisla.push(znak);
        } else if znak.is_ascii_alphabetic() {
            jednotka.push(znak.to_ascii_lowercase());
        } else if znak.is_whitespace() {
            continue;
        } else {
            return None;
        }
    }

    if cisla.is_empty() || jednotka.is_empty() {
        return None;
    }

    let hodnota: u128 = cisla.parse().ok()?;

    match jednotka.as_str() {
        "b" => Some(hodnota),
        "kb" => hodnota.checked_mul(1024),
        "mb" => hodnota.checked_mul((1024_u128).pow(2)),
        "gb" => hodnota.checked_mul((1024_u128).pow(3)),
        _ => None,
    }
}

fn potvrd_velikost() -> io::Result<bool> {
    let mut resp = String::new();
    loop {
        resp.clear();
        print!("requested size exceeds 1gb, continue? (y/N): ");
        io::stdout().flush()?;
        io::stdin().read_line(&mut resp)?;

        let resp = resp.trim().to_ascii_lowercase();
        if resp.is_empty() || resp == "n" || resp == "no" {
            return Ok(false);
        }
        if resp == "y" || resp == "yes" {
            return Ok(true);
        }
        println!("answer y or n");
    }
}

fn priprav_temp_file(exec_path: &Path, cilovy_bajty: u128) -> io::Result<PathBuf> {
    let mut temp_jmeno = exec_path
        .file_name()
        .map(|jmeno| jmeno.to_os_string())
        .unwrap_or_else(|| OsString::from("dynamic-sizer"));
    temp_jmeno.push(".tmp");
    let temp_path = exec_path.with_file_name(temp_jmeno);

    fs::copy(exec_path, &temp_path)?;

    let cilovy_bajty_u64 = cilovy_bajty as u64;
    let soubor = File::options().write(true).open(&temp_path)?;
    soubor.set_len(cilovy_bajty_u64)?;
    soubor.sync_all()?;

    Ok(temp_path)
}

fn spust_script(sc_target: &Path, sc_source: &Path) -> io::Result<()> {
    let mut nazev_sc = sc_target
        .file_name()
        .map(|jmeno| jmeno.to_os_string())
        .unwrap_or_else(|| OsString::from("dynamic-sizer"));
    nazev_sc.push(".swap.bat");
    let sc_path = sc_target.with_file_name(nazev_sc);

    if sc_path.exists() {
        let _ = fs::remove_file(&sc_path);
    }

    let sc_target_text = sc_target.as_os_str().to_string_lossy().into_owned();
    let sc_source_text = sc_source.as_os_str().to_string_lossy().into_owned();
    let obsah = format!(
        concat!(
            "@echo off\r\n",
            "setlocal enableextensions\r\n",
            "set \"SOURCE={sc_source_text}\"\r\n",
            "set \"TARGET={sc_target_text}\"\r\n",
            "for /L %%I in (1,1,300) do (\r\n",
            "    timeout /t 1 >nul\r\n",
            "    del /f /q \"%TARGET%\" >nul 2>&1\r\n",
            "    if exist \"%TARGET%\" (\r\n",
            "        rem stale zamknuto\r\n",
            "    ) else (\r\n",
            "        move /Y \"%SOURCE%\" \"%TARGET%\" >nul 2>&1\r\n",
            "        if exist \"%SOURCE%\" (\r\n",
            "            rem nelze presunout\r\n",
            "        ) else (\r\n",
            "            goto hotovo\r\n",
            "        )\r\n",
            "    )\r\n",
            ")\r\n",
            ":hotovo\r\n",
            "if exist \"%SOURCE%\" del /f /q \"%SOURCE%\" >nul 2>&1\r\n",
            "del \"%~f0\" >nul 2>&1\r\n"
        ),
        sc_source_text = sc_source_text,
        sc_target_text = sc_target_text
    );

    fs::write(&sc_path, obsah)?;

    Command::new("cmd").arg("/C").arg(&sc_path).spawn()?;

    Ok(())
}

fn formatuj_velikost(bajty: u128) -> String {
    const JEDNOTKY: [(&str, u128); 4] = [
        ("GB", (1024_u128).pow(3)),
        ("MB", (1024_u128).pow(2)),
        ("KB", 1024_u128),
        ("B", 1),
    ];

    for (nazev, delitel) in JEDNOTKY {
        if bajty >= delitel {
            let hodnota = (bajty as f64) / (delitel as f64);
            return format!("{:.2} {}", hodnota, nazev);
        }
    }

    "0 B".to_string()
}
