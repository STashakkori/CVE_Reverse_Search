use quick_xml::Reader;
use quick_xml::events::Event;
use std::fs::File;
use std::io::{BufReader};
use std::str;
use std::env;
use std::io::Write;
use std::fs;

fn main() {
  let args: Vec<String> = env::args().collect();
  if args.len() < 3 {
    println!("\x1b[38;5;208mToo few arguments.\x1b[0m");
    return;
  }
  if args.len() > 4 {
    println!("\x1b[38;5;208mToo many arguments.\x1b[0m");
    return;
  }
  let cve_path = args[1].trim(); // Path to local .xml db
  let find_this = args[2].trim(); // String to search for in the db
  let f_or_c = args[3].trim(); // Option to write to file or console

  if cve_path.len() < 1 {
    println!("\x1b[38;5;208mInvalid path to CVE database.\x1b[0m");
    return;
  }

  if find_this.len() < 3 {
    println!("\x1b[38;5;208mSearch string is too small.\x1b[0m");
    return;
  }

  if !f_or_c.eq("c") && !f_or_c.eq("C") && !f_or_c.eq("f") && !f_or_c.eq("F") {
    println!("\x1b[38;5;208mInvalid f_or_c option.\x1b[0m");
    return;
  }

  println!("\x1b[38;5;208mProcessing database...\x1b[0m");
  let file = match File::open(cve_path) {
    Ok(f) => f,
    Err(e) => { println!("\x1b[38;5;208mError opening db file: {}\x1b[0m", e); return; }
  };

  let mut out_name = String::from("out/cve/");
  out_name.push_str(find_this);
  out_name.push_str("_cve.txt");
  let mut outfile = match File::create(&out_name) {
    Ok(f) => f,
    Err(e) => { println!("\x1b[38;5;208mError creating outfile: {}\x1b[0m", e); return; }
  };
  let prereader = BufReader::new(file);
  let mut reader = Reader::from_reader(Box::new(prereader));
  reader.trim_text(true).expand_empty_elements(true);
  let mut buf = Vec::new(); 
  let mut txt = Vec::new();

  // Loop through xml starts here
  loop {
    match reader.read_event(&mut buf) {
      Ok(Event::Start(ref e)) if e.name() == b"Title" => {
        let entry = match reader.read_text(b"Title", &mut Vec::new()) {
          Ok(r) => r,
          Err(e) => { println!("\x1b[38;5;208mError reading xml: {}\x1b[0m", e); return; }
        };
        txt.push(entry);
      }
      Ok(Event::Start(ref e)) if e.name() == b"Note" => {
        let attr = &e.attributes().map(|a| a.unwrap()).collect::<Vec<_>>()[1];
        let desc = &attr.value;
        unsafe {
          let desc_str = str::from_utf8_unchecked(&desc);
          if desc_str.eq("Description") {
            let desc_val = match reader.read_text(b"Note", &mut Vec::new()) {
              Ok(x) => x,
              Err(_) => continue,
            };
            if desc_val.contains(find_this) {
              if f_or_c.eq("c") || f_or_c.eq("C") { 
                println!("\x1b[38;5;89mEntry found: \x1b[0m\x1b[38;5;86m{}\x1b[0m", txt[0]);
              }
              else {
                match writeln!(outfile, "{}\n", txt[0]) {
                  Ok(_) => (),
                  Err(_) => { println!("\x1b[38;5;208mError writing to file\x1b[0m"); return; }
                }
                match writeln!(outfile, "{}", textwrap::fill(&desc_val, 68)) {
                  Ok(_) => (),
                  Err(_) => { println!("\x1b[38;5;208mError writing to file.\x1b[0m"); return; }
                }
                let blank = "";
                match writeln!(outfile, "{:=>70}", blank) {
                  Ok(_) => (),
                  Err(_) => { println!("\x1b[38;5;208mError writing to file.\x1b[0m"); return; }
                }
                println!("\x1b[38;5;89mEntry found: \x1b[0m\x1b[38;5;86m{}\x1b[0m", txt[0]);
              }
            }
            txt = Vec::new();
          }
        }
      }, 
      Ok(Event::Eof) => break, // exits the loop when reaching end of file
      Err(e) => println!("\x1b[38;5;208mError in buffered reader: {}\x1b[0m",  e),
      _ => (), // There are several other `Event`s we do not consider here
    }
    buf.clear();
  }
  if f_or_c.eq("c") || f_or_c.eq("C") { 
    match fs::remove_file(out_name){ 
      Ok(_) => (),
      Err(_) => { println!("\x1b[38;5;208mFile deletion failed.\x1b[0m"); return; }
    } 
    println!("\x1b[38;5;208mProcessing complete.\x1b[0m");
  }
  else {
    println!("\x1b[38;5;208mProcessing complete. Entry details written to: {}.\x1b[0m", out_name);
  }
}
