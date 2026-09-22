//! CEL-JSON (CEL v1.1 section 5.2, the JSON side of the `JC<>` labels): a log
//! is a JSON array of records
//! `{"recnum", "pcr" | "nv_index", "digests": [{"hashAlg", "digest"}], "content_type", "content"}`
//! with byte strings as hex (TPM2B, as the CEL v1.0 example writes them).
//! An object that repeats a member name, or carries one the CDDL does not
//! define, is refused.

use crate::cel_cbor::check_extensions;
use crate::error::{Error, Result};
use crate::json::{bad, hex_bytes, narrow, string, text, uint, Members, J};
use crate::model::*;
use crate::pcclient::event_type_name;
use crate::HashAlg;

/// Decode a CEL-JSON log.
pub fn decode_json(data: &[u8], extensions: &[&'static ContentType]) -> Result<Vec<Record>> {
    check_extensions(extensions)?;
    let J::Arr(items) = crate::json::parse(data)? else {
        return Err(Error::Json("a log is a JSON array of records".into()));
    };
    if items.len() > MAX_RECORDS {
        return Err(Error::Json(format!("more than {MAX_RECORDS} records")));
    }
    let records = items
        .iter()
        .enumerate()
        .map(|(position, item)| decode_record(item, position, extensions))
        .collect::<Result<Vec<_>>>()?;
    check_recnums(&records)?;
    Ok(records)
}

fn decode_record(v: &J, position: usize, extensions: &[&'static ContentType]) -> Result<Record> {
    let what = format!("record {position}");
    let mut m = Members::new(v, what.clone())?;
    let recnum = uint(m.req("recnum")?, &format!("{what}.recnum"))?;
    let index = match (m.take("pcr"), m.take("nv_index")) {
        (Some(p), None) => Index::Pcr(narrow(p, &format!("{what}.pcr"))?),
        (None, Some(n)) => Index::Nv(narrow(n, &format!("{what}.nv_index"))?),
        _ => return Err(bad(&what, "exactly one of pcr and nv_index")),
    };
    let J::Arr(list) = m.req("digests")? else {
        return Err(bad(&format!("{what}.digests"), "expected an array"));
    };
    if list.is_empty() || list.len() > MAX_DIGESTS {
        return Err(bad(&format!("{what}.digests"), "1 to 16 entries"));
    }
    let mut digests = Vec::with_capacity(list.len());
    for (i, d) in list.iter().enumerate() {
        let w = format!("{what}.digests[{i}]");
        let mut dm = Members::new(d, w.clone())?;
        let name = text(dm.req("hashAlg")?, &w)?;
        let alg = HashAlg::from_json(name).ok_or_else(|| bad(&w, format!("hashAlg {name:?}")))?;
        let value = hex_bytes(dm.req("digest")?, &w, MAX_DIGEST_LEN)?;
        dm.finish()?;
        digests.push(Digest { alg, value });
    }
    let content_type = text(m.req("content_type")?, &format!("{what}.content_type"))?;
    let content_v = m.req("content")?;
    m.finish()?;
    let content = decode_content(
        content_type,
        content_v,
        &format!("{what}.content"),
        extensions,
    )?;
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
    name: &str,
    v: &J,
    what: &str,
    extensions: &[&'static ContentType],
) -> Result<Content> {
    Ok(match name {
        "cel" => {
            let mut m = Members::new(v, what.to_string())?;
            let ty = text(m.req("type")?, what)?;
            let mgmt = match ty {
                "firmware_end" => CelMgmt::FirmwareEnd,
                "cel_version" => {
                    let mut d = Members::new(m.req("data")?, format!("{what}.data"))?;
                    let major = narrow(d.req("major")?, what)?;
                    let minor = narrow(d.req("minor")?, what)?;
                    d.finish()?;
                    CelMgmt::Version { major, minor }
                }
                "cel_timestamp" => CelMgmt::Timestamp(uint(m.req("data")?, what)?),
                "state_trans" => {
                    let s = text(m.req("data")?, what)?;
                    CelMgmt::StateTrans(
                        StateTrans::from_name(s)
                            .ok_or_else(|| bad(what, format!("state_trans {s:?}")))?,
                    )
                }
                other => return Err(bad(what, format!("CEL management type {other:?}"))),
            };
            m.finish()?;
            Content::Cel(mgmt)
        }
        "pcclient_std" => {
            let mut m = Members::new(v, what.to_string())?;
            let event_type = match m.req("event_type")? {
                J::Str(s) if !s.is_empty() && s.len() <= MAX_BYTES => EventType::from_text(s),
                other => EventType::Code(narrow(other, &format!("{what}.event_type"))?),
            };
            let event_data = hex_bytes(m.req("event_data")?, what, MAX_BYTES)?;
            m.finish()?;
            Content::PcClientStd {
                event_type,
                event_data,
            }
        }
        "ima_template" => {
            let mut m = Members::new(v, what.to_string())?;
            let template_name = text(m.req("template_name")?, what)?.to_string();
            let template_data = hex_bytes(m.req("template_data")?, what, MAX_BYTES)?;
            m.finish()?;
            Content::ImaTemplate {
                template_name,
                template_data,
            }
        }
        "ima_tlv" => Content::ImaTlv(hex_bytes(v, what, MAX_BYTES)?),
        "systemd" => Content::Systemd(hex_bytes(v, what, MAX_BYTES)?),
        other => match extensions.iter().find(|e| e.name == other) {
            Some(ty) => Content::Extension {
                ty,
                value: decode_value(v, ty.schema, what)?,
            },
            None => return Err(bad(what, format!("unknown content_type {other:?}"))),
        },
    })
}

fn decode_value(v: &J, schema: Schema, what: &str) -> Result<Value> {
    Ok(match schema {
        Schema::Uint => Value::Uint(uint(v, what)?),
        Schema::Text => Value::Text(text(v, what)?.to_string()),
        Schema::Bytes => Value::Bytes(hex_bytes(v, what, MAX_BYTES)?),
        Schema::Map(fields) => {
            let mut m = Members::new(v, what.to_string())?;
            let mut out = Vec::with_capacity(fields.len());
            for f in fields {
                match m.take(f.name) {
                    Some(fv) => out.push((
                        f.key,
                        decode_value(fv, f.schema, &format!("{what}.{}", f.name))?,
                    )),
                    None if f.optional => {}
                    None => return Err(bad(what, format!("missing {}", f.name))),
                }
            }
            m.finish()?;
            Value::Map(out)
        }
    })
}

/// Encode a log as CEL-JSON. Content of an unregistered type has no
/// CEL-JSON name and is refused.
pub fn encode_json(records: &[Record]) -> Result<String> {
    check_recnums(records)?;
    let mut out = String::from("[");
    for (position, r) in records.iter().enumerate() {
        r.validate(position)?;
        if position > 0 {
            out.push(',');
        }
        out.push_str(&format!("{{\"recnum\":{},", r.recnum));
        match r.index {
            Index::Pcr(n) => out.push_str(&format!("\"pcr\":{n},")),
            Index::Nv(n) => out.push_str(&format!("\"nv_index\":{n},")),
        }
        out.push_str("\"digests\":[");
        for (i, d) in r.digests.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str("{\"hashAlg\":");
            string(&d.alg.to_json(), &mut out);
            out.push_str(&format!(",\"digest\":\"{}\"}}", hex::encode(&d.value)));
        }
        out.push_str("],\"content_type\":");
        match &r.content {
            Content::Cel(m) => {
                out.push_str("\"cel\",\"content\":{\"type\":");
                match m {
                    CelMgmt::FirmwareEnd => out.push_str("\"firmware_end\""),
                    CelMgmt::Version { major, minor } => out.push_str(&format!(
                        "\"cel_version\",\"data\":{{\"major\":{major},\"minor\":{minor}}}"
                    )),
                    CelMgmt::Timestamp(t) => {
                        out.push_str(&format!("\"cel_timestamp\",\"data\":{t}"))
                    }
                    CelMgmt::StateTrans(s) => {
                        out.push_str(&format!("\"state_trans\",\"data\":\"{}\"", s.name()))
                    }
                }
                out.push('}');
            }
            Content::PcClientStd {
                event_type,
                event_data,
            } => {
                out.push_str("\"pcclient_std\",\"content\":{\"event_type\":");
                match event_type {
                    EventType::Code(c) => match event_type_name(*c) {
                        Some(n) => string(n, &mut out),
                        None => out.push_str(&c.to_string()),
                    },
                    EventType::Name(n) => string(n, &mut out),
                }
                out.push_str(&format!(",\"event_data\":\"{}\"}}", hex::encode(event_data)));
            }
            Content::ImaTemplate {
                template_name,
                template_data,
            } => {
                out.push_str("\"ima_template\",\"content\":{\"template_name\":");
                string(template_name, &mut out);
                out.push_str(&format!(
                    ",\"template_data\":\"{}\"}}",
                    hex::encode(template_data)
                ));
            }
            Content::ImaTlv(b) => {
                out.push_str(&format!("\"ima_tlv\",\"content\":\"{}\"", hex::encode(b)))
            }
            Content::Systemd(b) => {
                out.push_str(&format!("\"systemd\",\"content\":\"{}\"", hex::encode(b)))
            }
            Content::Extension { ty, value } => {
                string(ty.name, &mut out);
                out.push_str(",\"content\":");
                write_value(value, ty.schema, &mut out);
            }
            Content::Unknown { content_type, .. } => {
                return Err(Error::Usage(format!(
                    "record {position}: content_type {content_type} has no CEL-JSON name; register it to write CEL-JSON"
                )))
            }
        }
        out.push('}');
    }
    out.push(']');
    Ok(out)
}

fn write_value(v: &Value, schema: Schema, out: &mut String) {
    match (v, schema) {
        (Value::Uint(n), _) => out.push_str(&n.to_string()),
        (Value::Text(s), _) => string(s, out),
        (Value::Bytes(b), _) => out.push_str(&format!("\"{}\"", hex::encode(b))),
        (Value::Map(entries), Schema::Map(fields)) => {
            out.push('{');
            for (i, (k, v)) in entries.iter().enumerate() {
                let f = fields
                    .iter()
                    .find(|f| f.key == *k)
                    .expect("validated against the schema");
                if i > 0 {
                    out.push(',');
                }
                string(f.name, out);
                out.push(':');
                write_value(v, f.schema, out);
            }
            out.push('}');
        }
        (Value::Map(_), _) => unreachable!("validated against the schema"),
    }
}
