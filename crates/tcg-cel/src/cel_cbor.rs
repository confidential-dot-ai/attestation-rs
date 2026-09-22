//! CEL-CBOR (CEL v1.1 section 5.2): records are the maps
//! `{0: recnum, 1: pcr / 2: nv_index, 3: digests, 9: content_type, 10: content}`
//! and a log is the CDDL's `tcg-canonical-event-log`, an array of them.

use crate::cbor::{self, Reader};
use crate::error::{Error, Result};
use crate::model::*;
use crate::HashAlg;

pub(crate) fn check_extensions(extensions: &[&'static ContentType]) -> Result<()> {
    for (i, e) in extensions.iter().enumerate() {
        e.check().map_err(Error::Usage)?;
        if extensions[..i]
            .iter()
            .any(|o| o.value == e.value || o.name == e.name)
        {
            return Err(Error::Usage(format!(
                "extension {} is registered twice",
                e.name
            )));
        }
    }
    Ok(())
}

/// Decode a CEL-CBOR log: one deterministic CBOR array of records, each
/// valid on its own and numbered from 0 per index.
pub fn decode_cbor(data: &[u8], extensions: &[&'static ContentType]) -> Result<Vec<Record>> {
    check_extensions(extensions)?;
    let mut r = Reader::new(data);
    let n = r.array(MAX_RECORDS)?;
    let mut out = Vec::with_capacity(n.min(4096));
    for position in 0..n {
        out.push(decode_record(&mut r, position, extensions)?);
    }
    if !r.at_end() {
        return Err(r.err(r.pos(), "bytes after the log"));
    }
    check_recnums(&out)?;
    Ok(out)
}

/// Decode records written back to back as a CBOR sequence (RFC 8742), the
/// shape of an append-only log file. The CEL CDDL's log is the array
/// [`decode_cbor`] reads and [`encode_cbor`] writes.
pub fn decode_cbor_sequence(
    data: &[u8],
    extensions: &[&'static ContentType],
) -> Result<Vec<Record>> {
    check_extensions(extensions)?;
    let mut r = Reader::new(data);
    let mut out = Vec::new();
    while !r.at_end() {
        if out.len() == MAX_RECORDS {
            return Err(r.err(r.pos(), format!("more than {MAX_RECORDS} records")));
        }
        let position = out.len();
        out.push(decode_record(&mut r, position, extensions)?);
    }
    check_recnums(&out)?;
    Ok(out)
}

fn decode_record(
    r: &mut Reader<'_>,
    position: usize,
    extensions: &[&'static ContentType],
) -> Result<Record> {
    let at = r.pos();
    if r.map(5)? != 5 {
        return Err(r.err(at, "a record is a map of five members"));
    }
    r.key(0, "recnum")?;
    let recnum = r.uint()?;
    let at_index = r.pos();
    let index = match r.uint()? {
        k @ (1 | 2) => {
            let at_value = r.pos();
            let v = u32::try_from(r.uint()?)
                .map_err(|_| r.err(at_value, "index does not fit 32 bits"))?;
            if k == 1 {
                Index::Pcr(v)
            } else {
                Index::Nv(v)
            }
        }
        k => {
            return Err(r.err(
                at_index,
                format!("expected key 1 (pcr) or 2 (nv_index), found {k}"),
            ))
        }
    };
    r.key(3, "digests")?;
    let at_digests = r.pos();
    let count = r.array(MAX_DIGESTS)?;
    if count == 0 {
        return Err(r.err(at_digests, "digests is empty"));
    }
    let mut digests = Vec::with_capacity(count);
    for _ in 0..count {
        let at = r.pos();
        if r.map(2)? != 2 {
            return Err(r.err(at, "a digest is a map of two members"));
        }
        r.key(0, "hashAlg")?;
        let at_alg = r.pos();
        let alg = u16::try_from(r.uint()?).map_err(|_| r.err(at_alg, "hashAlg exceeds 16 bits"))?;
        r.key(1, "digest")?;
        let value = r.bstr(MAX_DIGEST_LEN)?.to_vec();
        digests.push(Digest {
            alg: HashAlg(alg),
            value,
        });
    }
    r.key(9, "content_type")?;
    let content_type = r.uint()?;
    r.key(10, "content")?;
    let content = decode_content(r, content_type, extensions)?;
    let rec = Record {
        recnum,
        index,
        digests,
        content,
    };
    rec.validate(position)?;
    Ok(rec)
}

fn decode_content(
    r: &mut Reader<'_>,
    content_type: u64,
    extensions: &[&'static ContentType],
) -> Result<Content> {
    let at = r.pos();
    Ok(match content_type {
        CONTENT_CEL => Content::Cel(decode_celmgt(r)?),
        CONTENT_PCCLIENT_STD => {
            if r.map(2)? != 2 {
                return Err(r.err(at, "pcclient_std content is a map of two members"));
            }
            r.key(0, "event_type")?;
            let at_type = r.pos();
            let event_type = match r.peek_major() {
                Some(0) => EventType::Code(
                    u32::try_from(r.uint()?)
                        .map_err(|_| r.err(at_type, "event_type exceeds 32 bits"))?,
                ),
                _ => EventType::from_text(r.tstr(MAX_BYTES)?),
            };
            r.key(1, "event_data")?;
            let event_data = r.bstr(MAX_BYTES)?.to_vec();
            Content::PcClientStd {
                event_type,
                event_data,
            }
        }
        CONTENT_IMA_TEMPLATE => {
            if r.map(2)? != 2 {
                return Err(r.err(at, "ima_template content is a map of two members"));
            }
            r.key(0, "template_name")?;
            let template_name = r.tstr(MAX_BYTES)?.to_string();
            r.key(1, "template_data")?;
            let template_data = r.bstr(MAX_BYTES)?.to_vec();
            Content::ImaTemplate {
                template_name,
                template_data,
            }
        }
        CONTENT_IMA_TLV => Content::ImaTlv(r.bstr(MAX_BYTES)?.to_vec()),
        CONTENT_SYSTEMD => Content::Systemd(r.bstr(MAX_BYTES)?.to_vec()),
        t if CONTENT_RESERVED.contains(&t) => {
            return Err(r.err(at, format!("content_type {t} is reserved")))
        }
        t => match extensions.iter().find(|e| e.value == t) {
            Some(ty) => Content::Extension {
                ty,
                value: decode_value(r, ty.schema)?,
            },
            None => {
                let item = r.item()?;
                if item.len() > MAX_BYTES {
                    return Err(r.err(at, "content too long"));
                }
                Content::Unknown {
                    content_type: t,
                    cbor: item.to_vec(),
                }
            }
        },
    })
}

fn decode_celmgt(r: &mut Reader<'_>) -> Result<CelMgmt> {
    let at = r.pos();
    let n = r.map(2)?;
    if n == 0 {
        return Err(r.err(at, "CEL management content is empty"));
    }
    r.key(0, "type")?;
    let at_type = r.pos();
    let ty = r.uint()?;
    if ty == CELMGT_FIRMWARE_END {
        return match n {
            1 => Ok(CelMgmt::FirmwareEnd),
            _ => Err(r.err(at, "firmware_end carries no data")),
        };
    }
    if n != 2 {
        return Err(r.err(at, "CEL management content is {type, data}"));
    }
    r.key(1, "data")?;
    let at_data = r.pos();
    match ty {
        CELMGT_VERSION => {
            if r.map(2)? != 2 {
                return Err(r.err(at_data, "cel_version is {major, minor}"));
            }
            r.key(0, "major")?;
            let major =
                u16::try_from(r.uint()?).map_err(|_| r.err(at_data, "major exceeds 16 bits"))?;
            r.key(1, "minor")?;
            let minor =
                u16::try_from(r.uint()?).map_err(|_| r.err(at_data, "minor exceeds 16 bits"))?;
            Ok(CelMgmt::Version { major, minor })
        }
        CELMGT_TIMESTAMP => Ok(CelMgmt::Timestamp(r.uint()?)),
        CELMGT_STATE_TRANS => {
            let v = r.uint()?;
            StateTrans::from_value(v)
                .map(CelMgmt::StateTrans)
                .ok_or_else(|| r.err(at_data, format!("state_trans {v} is not defined")))
        }
        t => Err(r.err(at_type, format!("CEL management type {t} is not defined"))),
    }
}

fn decode_value(r: &mut Reader<'_>, schema: Schema) -> Result<Value> {
    Ok(match schema {
        Schema::Uint => Value::Uint(r.uint()?),
        Schema::Text => Value::Text(r.tstr(MAX_BYTES)?.to_string()),
        Schema::Bytes => Value::Bytes(r.bstr(MAX_BYTES)?.to_vec()),
        Schema::Map(fields) => {
            let at = r.pos();
            let n = r.map(fields.len())?;
            let mut out = Vec::with_capacity(n);
            let mut next = 0usize;
            for _ in 0..n {
                let at_key = r.pos();
                let key = r.uint()?;
                let i = fields[next..]
                    .iter()
                    .position(|f| f.key == key)
                    .map(|i| next + i)
                    .ok_or_else(|| {
                        r.err(
                            at_key,
                            format!("key {key} is unknown, repeated or out of order"),
                        )
                    })?;
                if let Some(f) = fields[next..i].iter().find(|f| !f.optional) {
                    return Err(r.err(at_key, format!("missing field {}", f.name)));
                }
                out.push((key, decode_value(r, fields[i].schema)?));
                next = i + 1;
            }
            if let Some(f) = fields[next..].iter().find(|f| !f.optional) {
                return Err(r.err(at, format!("missing field {}", f.name)));
            }
            Value::Map(out)
        }
    })
}

/// Encode a log as CEL-CBOR: the array of records, each checked against the
/// information model and numbered from 0 per index.
pub fn encode_cbor(records: &[Record]) -> Result<Vec<u8>> {
    if records.len() > MAX_RECORDS {
        return Err(Error::Usage(format!("more than {MAX_RECORDS} records")));
    }
    check_recnums(records)?;
    let mut out = Vec::new();
    cbor::array(records.len(), &mut out);
    for (position, r) in records.iter().enumerate() {
        r.validate(position)?;
        write_record(r, &mut out);
    }
    Ok(out)
}

/// Encode one record, for appending to a CBOR sequence file.
pub fn encode_cbor_record(record: &Record) -> Result<Vec<u8>> {
    record.validate(0)?;
    let mut out = Vec::new();
    write_record(record, &mut out);
    Ok(out)
}

fn write_record(r: &Record, out: &mut Vec<u8>) {
    cbor::map(5, out);
    cbor::uint(0, out);
    cbor::uint(r.recnum, out);
    match r.index {
        Index::Pcr(n) => {
            cbor::uint(1, out);
            cbor::uint(u64::from(n), out);
        }
        Index::Nv(n) => {
            cbor::uint(2, out);
            cbor::uint(u64::from(n), out);
        }
    }
    cbor::uint(3, out);
    cbor::array(r.digests.len(), out);
    for d in &r.digests {
        cbor::map(2, out);
        cbor::uint(0, out);
        cbor::uint(u64::from(d.alg.0), out);
        cbor::uint(1, out);
        cbor::bstr(&d.value, out);
    }
    cbor::uint(9, out);
    cbor::uint(r.content.content_type(), out);
    cbor::uint(10, out);
    write_content(&r.content, out);
}

fn write_content(c: &Content, out: &mut Vec<u8>) {
    match c {
        Content::Cel(m) => match m {
            CelMgmt::FirmwareEnd => {
                cbor::map(1, out);
                cbor::uint(0, out);
                cbor::uint(CELMGT_FIRMWARE_END, out);
            }
            CelMgmt::Version { major, minor } => {
                cbor::map(2, out);
                cbor::uint(0, out);
                cbor::uint(CELMGT_VERSION, out);
                cbor::uint(1, out);
                cbor::map(2, out);
                cbor::uint(0, out);
                cbor::uint(u64::from(*major), out);
                cbor::uint(1, out);
                cbor::uint(u64::from(*minor), out);
            }
            CelMgmt::Timestamp(t) => {
                cbor::map(2, out);
                cbor::uint(0, out);
                cbor::uint(CELMGT_TIMESTAMP, out);
                cbor::uint(1, out);
                cbor::uint(*t, out);
            }
            CelMgmt::StateTrans(s) => {
                cbor::map(2, out);
                cbor::uint(0, out);
                cbor::uint(CELMGT_STATE_TRANS, out);
                cbor::uint(1, out);
                cbor::uint(s.value(), out);
            }
        },
        Content::PcClientStd {
            event_type,
            event_data,
        } => {
            cbor::map(2, out);
            cbor::uint(0, out);
            match event_type {
                EventType::Code(c) => cbor::uint(u64::from(*c), out),
                EventType::Name(n) => cbor::tstr(n, out),
            }
            cbor::uint(1, out);
            cbor::bstr(event_data, out);
        }
        Content::ImaTemplate {
            template_name,
            template_data,
        } => {
            cbor::map(2, out);
            cbor::uint(0, out);
            cbor::tstr(template_name, out);
            cbor::uint(1, out);
            cbor::bstr(template_data, out);
        }
        Content::ImaTlv(b) | Content::Systemd(b) => cbor::bstr(b, out),
        Content::Extension { value, .. } => write_value(value, out),
        Content::Unknown { cbor: raw, .. } => out.extend_from_slice(raw),
    }
}

fn write_value(v: &Value, out: &mut Vec<u8>) {
    match v {
        Value::Uint(n) => cbor::uint(*n, out),
        Value::Text(s) => cbor::tstr(s, out),
        Value::Bytes(b) => cbor::bstr(b, out),
        Value::Map(entries) => {
            cbor::map(entries.len(), out);
            for (k, v) in entries {
                cbor::uint(*k, out);
                write_value(v, out);
            }
        }
    }
}
