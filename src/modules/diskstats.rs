use std::{io::{Error, ErrorKind}, fs::File, io::{BufRead, BufReader}};
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskStat {
    pub major: i32,
    pub minor: i32,
    pub name: String,
    pub reads: u64,
    pub merged: u64,
    pub sectors_read: u64,
    pub time_reading: u64,
    pub writes: u64,
    pub writes_merged: u64,
    pub sectors_written: u64,
    pub time_writing: u64,
    pub in_progress: u64,
    pub time_in_progress: u64,
    pub weighted_time_in_progress: u64,
    pub discards: Option<u64>,
    pub discards_merged: Option<u64>,
    pub sectors_discarded: Option<u64>,
    pub time_discarding: Option<u64>,
    pub flushes: Option<u64>,
    pub time_flushing: Option<u64>,
}


pub fn read_current() -> Vec<DiskStat> {
    let mut disk_stats = Vec::new();
    let diskstats = "/proc/diskstats";

    let file = File::open(diskstats).expect("Failed to open /proc/diskstats");
    let reader = BufReader::new(file);

    for line in reader.lines() {
        let line = line.expect("Failed to read line");
        if !line.contains("loop") && !line.contains("dm-") && !line.contains("sr0") {
            let disk_stat = DiskStat::from_line(&line).expect("Failed to parse line");
            disk_stats.push(disk_stat);
        }
    }

    disk_stats
}

impl DiskStat {
    pub fn from_line(line: &str) -> Result<DiskStat, Error> {
        let mut parts = line.split_whitespace();
        
        let parse_next = |parts: &mut std::str::SplitWhitespace| -> Result<String, Error> {
            parts.next()
                .ok_or_else(|| Error::new(ErrorKind::InvalidData, "Insufficient data in line"))
                .map(String::from)
        };

        let parse_next_num = |parts: &mut std::str::SplitWhitespace| -> Result<u64, Error> {
            parse_next(parts)?
                .parse()
                .map_err(|_| Error::new(ErrorKind::InvalidData, "Failed to parse number"))
        };

        Ok(DiskStat {
            major: parse_next(&mut parts)?.parse().map_err(|_| Error::new(ErrorKind::InvalidData, "Failed to parse major"))?,
            minor: parse_next(&mut parts)?.parse().map_err(|_| Error::new(ErrorKind::InvalidData, "Failed to parse minor"))?,
            name: format!("/dev/{}", parse_next(&mut parts)?),
            reads: parse_next_num(&mut parts)?,
            merged: parse_next_num(&mut parts)?,
            sectors_read: parse_next_num(&mut parts)?,
            time_reading: parse_next_num(&mut parts)?,
            writes: parse_next_num(&mut parts)?,
            writes_merged: parse_next_num(&mut parts)?,
            sectors_written: parse_next_num(&mut parts)?,
            time_writing: parse_next_num(&mut parts)?,
            in_progress: parse_next_num(&mut parts)?,
            time_in_progress: parse_next_num(&mut parts)?,
            weighted_time_in_progress: parse_next_num(&mut parts)?,
            discards: parse_next_num(&mut parts).ok(),
            discards_merged: parse_next_num(&mut parts).ok(),
            sectors_discarded: parse_next_num(&mut parts).ok(),
            time_discarding: parse_next_num(&mut parts).ok(),
            flushes: parse_next_num(&mut parts).ok(),
            time_flushing: parse_next_num(&mut parts).ok(),
        })
    }
}