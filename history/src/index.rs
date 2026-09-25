//! Bounded external merge sort. Index entries retain arrival order and alternatives.
use crate::{
    bad,
    codec::{Decoder, Encoder},
    journal::{remove_owned, Quota},
    Error, Result,
};
use std::{
    cmp::Reverse,
    collections::BinaryHeap,
    fs::{self, File, OpenOptions},
    io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    path::Path,
};

pub const WIDTH: usize = 112;
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Row {
    pub generation: [u8; 32],
    pub direction: u8,
    pub selected: bool,
    pub start: i64,
    pub end: i64,
    pub record_offset: u64,
    pub record_digest: [u8; 32],
    pub ordinal: u64,
}
impl Row {
    fn key(&self) -> ([u8; 32], u8, i64, i64, u64, u64, bool, [u8; 32]) {
        (
            self.generation,
            self.direction,
            self.start,
            self.end,
            self.ordinal,
            self.record_offset,
            self.selected,
            self.record_digest,
        )
    }
    pub fn encode(&self) -> Result<[u8; WIDTH]> {
        if self.direction > 1
            || self.end <= self.start
            || self.end.checked_sub(self.start).is_none_or(|n| n > 65535)
            || self.ordinal == 0
        {
            return Err(bad("history_index", "invalid interval"));
        }
        let mut e = Encoder::default();
        e.hash(&self.generation);
        e.u8(self.direction);
        e.u8(u8::from(self.selected));
        e.0.extend_from_slice(&[0; 6]);
        e.i64(self.start);
        e.i64(self.end);
        e.u64(self.record_offset);
        e.hash(&self.record_digest);
        e.u64(self.ordinal);
        e.u64(0);
        let mut out = [0; WIDTH];
        out.copy_from_slice(&e.0);
        Ok(out)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != WIDTH {
            return Err(bad("history_index", "wrong entry width"));
        }
        let mut d = Decoder::new(bytes);
        let generation = d.hash()?;
        let direction = d.u8()?;
        let selected = d.boolean()?;
        if d.take(6)? != [0; 6] {
            return Err(bad("history_index", "reserved bytes set"));
        }
        let r = Self {
            generation,
            direction,
            selected,
            start: d.i64()?,
            end: d.i64()?,
            record_offset: d.u64()?,
            record_digest: d.hash()?,
            ordinal: d.u64()?,
        };
        if d.u64()? != 0 {
            return Err(bad("history_index", "reserved bytes set"));
        }
        d.finish()?;
        r.encode()?;
        Ok(r)
    }
}
impl Ord for Row {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.key().cmp(&other.key())
    }
}
impl PartialOrd for Row {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
fn read_row(f: &mut impl Read) -> Result<Option<Row>> {
    let mut b = [0; WIDTH];
    let mut n = 0;
    while n < WIDTH {
        let k = f.read(&mut b[n..])?;
        if k == 0 {
            if n == 0 {
                return Ok(None);
            }
            return Err(bad("history_index", "partial entry"));
        }
        n += k;
    }
    Ok(Some(Row::decode(&b)?))
}
fn write_row(f: &mut impl Write, r: &Row, q: &Quota) -> Result<()> {
    q.borrow_mut().charge(WIDTH as u64)?;
    f.write_all(&r.encode()?)?;
    Ok(())
}
pub fn append(f: &mut File, r: &Row, q: &Quota) -> Result<()> {
    write_row(f, r, q)
}
/// Constant-sized chunk and fan-in, irrespective of total journal size. Temporary
/// bytes count against the same disk quota; all runs are workspace-owned files.
pub fn sort(root: &Path, entries: usize, fan_in: usize, q: &Quota) -> Result<u64> {
    sort_checked(root, entries, fan_in, q, || Ok(()))
}
/// Cooperatively interrupt all merge phases. Completed runs remain unsealed.
pub fn sort_checked(
    root: &Path,
    entries: usize,
    fan_in: usize,
    q: &Quota,
    mut check: impl FnMut() -> Result<()>,
) -> Result<u64> {
    if !(2..=1_000_000).contains(&entries) || !(2..=64).contains(&fan_in) {
        return Err(bad("history_sort", "invalid sort budgets"));
    }
    let input = root.join("placements.raw");
    let mut source = BufReader::with_capacity(65536, File::open(&input)?);
    let runs = root.join("sort");
    fs::create_dir(&runs)?;
    let mut count = 0u64;
    let mut total = 0u64;
    loop {
        check()?;
        let mut chunk = Vec::with_capacity(entries);
        while chunk.len() < entries {
            if chunk.len() % 4096 == 0 {
                check()?;
            }
            match read_row(&mut source)? {
                Some(r) => chunk.push(r),
                None => break,
            }
        }
        if chunk.is_empty() {
            break;
        }
        chunk.sort();
        let path = runs.join(format!("0-{count}.idx"));
        let mut out = BufWriter::with_capacity(
            65536,
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)?,
        );
        for r in &chunk {
            write_row(&mut out, r, q)?;
            total = total
                .checked_add(1)
                .ok_or_else(|| Error::limit("history_index_count"))?;
        }
        out.flush()?;
        out.get_ref().sync_all()?;
        count += 1;
    }
    drop(source);
    remove_owned(&input, q)?;
    if count == 0 {
        let f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(root.join("ranges.idx"))?;
        f.sync_all()?;
        fs::remove_dir(runs)?;
        return Ok(0);
    }
    let mut pass = 0u64;
    while count > 1 {
        let mut next = 0u64;
        let mut first = 0u64;
        while first < count {
            check()?;
            let end = count.min(first + fan_in as u64);
            let mut files = Vec::new();
            let mut heap = BinaryHeap::new();
            for n in first..end {
                let mut f = BufReader::with_capacity(
                    65536,
                    File::open(runs.join(format!("{pass}-{n}.idx")))?,
                );
                if let Some(r) = read_row(&mut f)? {
                    heap.push(Reverse((r, files.len())));
                }
                files.push(f);
            }
            let path = runs.join(format!("{}-{next}.idx", pass + 1));
            let mut out = BufWriter::with_capacity(
                65536,
                OpenOptions::new().write(true).create_new(true).open(path)?,
            );
            let mut merged = 0usize;
            while let Some(Reverse((r, i))) = heap.pop() {
                if merged % 4096 == 0 {
                    check()?;
                }
                merged += 1;
                write_row(&mut out, &r, q)?;
                if let Some(n) = read_row(&mut files[i])? {
                    heap.push(Reverse((n, i)));
                }
            }
            out.flush()?;
            out.get_ref().sync_all()?;
            drop(files);
            for n in first..end {
                remove_owned(&runs.join(format!("{pass}-{n}.idx")), q)?;
            }
            first = end;
            next += 1;
        }
        pass += 1;
        count = next;
    }
    fs::rename(runs.join(format!("{pass}-0.idx")), root.join("ranges.idx"))?;
    fs::remove_dir(runs)?;
    Ok(total)
}
pub struct Index {
    file: File,
    pub count: u64,
}
impl Index {
    pub fn open(path: &Path) -> Result<Self> {
        crate::journal::regular(path)?;
        let file = File::open(path)?;
        let n = file.metadata()?.len();
        if n % WIDTH as u64 != 0 {
            return Err(bad("history_index", "misaligned index"));
        }
        Ok(Self {
            file,
            count: n / WIDTH as u64,
        })
    }
    pub fn at(&mut self, n: u64) -> Result<Row> {
        if n >= self.count {
            return Err(bad("history_index", "entry outside index"));
        }
        self.file.seek(SeekFrom::Start(
            n.checked_mul(WIDTH as u64)
                .ok_or_else(|| Error::limit("history_index_offset"))?,
        ))?;
        read_row(&mut self.file)?.ok_or_else(|| bad("history_index", "unexpected EOF"))
    }
    pub fn lower_bound(&mut self, generation: [u8; 32], direction: u8, start: i64) -> Result<u64> {
        let mut lo = 0;
        let mut hi = self.count;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let r = self.at(mid)?;
            if (r.generation, r.direction, r.start) < (generation, direction, start) {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        Ok(lo)
    }
}
